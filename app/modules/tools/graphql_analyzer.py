import re
import json
from typing import Dict, List, Any, Optional
from collections import defaultdict
from app.utils.logger import get_logger

logger = get_logger()

class GraphQLAnalyzer:
    """
    Analyzes GraphQL schema from introspection result.
    Extracts types, fields, arguments, and generates sample queries/mutations.
    Flags security-relevant fields and arguments (IDORs, PII, Secrets).

    CHANGES vs. original:
      - _build_arg_value(): recursively expands INPUT_OBJECT arguments (required
        fields only) and resolves ENUM defaults from enumValues, so generated
        mutations are syntactically valid and runnable. Requires the scanner's
        upgraded introspection query (inputFields + enumValues).
      - find_dangerous_fields(): token-based matching instead of substring, so
        'monkey'/'keyboard'/'author' no longer match 'key'/'auth'. 'key' only
        flags when paired with a sensitive sibling (api/secret/private/access).
    """

    # sensitive single tokens (matched as whole tokens, not substrings)
    _SENSITIVE_TOKENS = {
        'password', 'passwd', 'pwd', 'token', 'secret', 'credential', 'credentials',
        'auth', 'apikey', 'ssn', 'private', 'admin', 'root', 'internal', 'bypass',
        'email', 'otp', 'mfa', 'seed', 'mnemonic', 'iban', 'cvv', 'payment', 'billing',
    }
    # sensitive concepts that only exist as multi-word field names
    _SENSITIVE_PAIRS = [
        {'credit', 'card'}, {'card', 'number'}, {'social', 'security'},
        {'private', 'key'}, {'api', 'key'}, {'secret', 'key'}, {'access', 'token'},
        {'account', 'number'}, {'routing', 'number'}, {'session', 'id'},
    ]

    def __init__(self, schema_data: Dict):
        self.schema = schema_data
        self.types = self._extract_types()
        self.type_map = {t['name']: t for t in self.types if t.get('name')}

        # Dynamically identify root operation types (usually Query/Mutation, but can be custom)
        schema_root = self.schema.get('data', {}).get('__schema', {})
        self.query_type_name = schema_root.get('queryType', {}).get('name') if schema_root.get('queryType') else 'Query'
        self.mutation_type_name = schema_root.get('mutationType', {}).get('name') if schema_root.get('mutationType') else 'Mutation'
        self.subscription_type_name = schema_root.get('subscriptionType', {}).get('name') if schema_root.get('subscriptionType') else 'Subscription'

        self.queries = self._extract_operation_fields(self.query_type_name)
        self.mutations = self._extract_operation_fields(self.mutation_type_name)
        self.subscriptions = self._extract_operation_fields(self.subscription_type_name)

    def _extract_types(self) -> List[Dict]:
        """Extract all types from introspection."""
        if not self.schema or 'data' not in self.schema:
            return []
        return self.schema['data'].get('__schema', {}).get('types', [])

    def _extract_operation_fields(self, root_name: str) -> List[Dict]:
        """Extract fields for a specific root operation type."""
        if not root_name:
            return []
        root_type = self.type_map.get(root_name)
        if not root_type:
            return []
        return root_type.get('fields') or []

    def resolve_type_ref(self, ref: Dict) -> str:
        """
        Recursively unwrap GraphQL modifiers (NON_NULL, LIST) to find the base type string.
        """
        if not ref or not isinstance(ref, dict):
            return "Unknown"

        if ref.get('kind') == 'NON_NULL':
            return f"{self.resolve_type_ref(ref.get('ofType', {}))}!"
        elif ref.get('kind') == 'LIST':
            return f"[{self.resolve_type_ref(ref.get('ofType', {}))}]"
        else:
            return ref.get('name') or "Unknown"

    def get_base_type_name(self, ref: Dict) -> str:
        """Returns just the raw type name without List '[]' or Non-Null '!' syntax."""
        name = self.resolve_type_ref(ref)
        return name.replace('[', '').replace(']', '').replace('!', '')

    # -----------------------------------------------------------------
    # NEW: valid argument-value construction
    # -----------------------------------------------------------------

    def _build_arg_value(self, type_ref: Dict, depth: int = 0, max_depth: int = 3) -> str:
        """
        Produce a syntactically valid dummy value for an argument type.
        Expands INPUT_OBJECT types (required fields only, to keep the payload
        minimal and avoid runaway recursion on deep input graphs) and resolves
        ENUM defaults from enumValues.
        """
        base = self.get_base_type_name(type_ref)
        tdef = self.type_map.get(base, {})
        kind = tdef.get('kind')

        if base in ('ID', 'String'):
            return '"example"'
        if base in ('Int', 'Float'):
            return '1'
        if base == 'Boolean':
            return 'false'
        if kind == 'ENUM':
            enum_vals = tdef.get('enumValues') or []
            return enum_vals[0]['name'] if enum_vals else 'null'
        if kind == 'INPUT_OBJECT' and depth < max_depth:
            parts = []
            for f in (tdef.get('inputFields') or []):
                ftype = f.get('type', {})
                # only fill required (NON_NULL) fields -> minimal valid payload
                if ftype.get('kind') == 'NON_NULL':
                    parts.append(f"{f.get('name')}: {self._build_arg_value(ftype, depth + 1, max_depth)}")
            return "{ " + ", ".join(parts) + " }" if parts else "{}"
        # custom scalar (DateTime, URL, JSON...) or unresolved -> string is safest
        return '"example"'

    def generate_sample_query(self, field: Dict, depth: int = 0, max_depth: int = 2) -> str:
        """
        Generate a sample GraphQL payload. Uses recursion limits to prevent infinite loops
        on circular schemas (e.g., User -> Friends -> User).
        """
        if depth >= max_depth:
            return ''

        field_name = field.get('name')
        if not field_name:
            return ''

        # Handle Arguments
        args = field.get('args', [])
        arg_parts = []
        for arg in args:
            # Skip optional arguments to keep payloads clean, unless it's the root level
            if depth > 0 and arg.get('type', {}).get('kind') != 'NON_NULL':
                continue

            arg_name = arg.get('name')
            # NEW: valid value construction incl. INPUT_OBJECT expansion + enum defaults
            default_val = self._build_arg_value(arg.get('type', {}))
            arg_parts.append(f"{arg_name}: {default_val}")

        arg_str = f"({', '.join(arg_parts)})" if arg_parts else ""

        # Handle Sub-fields (Return Types)
        base_return_type = self.get_base_type_name(field.get('type', {}))
        type_def = self.type_map.get(base_return_type)

        nested_fields = []
        if type_def and type_def.get('kind') in ['OBJECT', 'INTERFACE']:
            # Pull a few scalar fields to flesh out the query
            for subfield in type_def.get('fields', [])[:5]:
                sub_base_type = self.get_base_type_name(subfield.get('type', {}))
                sub_def = self.type_map.get(sub_base_type, {})

                if sub_def.get('kind') in ['SCALAR', 'ENUM']:
                    nested_fields.append(subfield.get('name'))
                elif depth + 1 < max_depth:
                    # Recurse for nested objects
                    nested_query = self.generate_sample_query(subfield, depth + 1, max_depth)
                    if nested_query:
                        nested_fields.append(nested_query)

        nested_str = ' '.join(nested_fields)
        if nested_str:
            return f"{field_name}{arg_str} {{ {nested_str} }}"
        return f"{field_name}{arg_str}"

    def generate_all_queries(self, max_depth: int = 2) -> Dict[str, str]:
        queries = {}
        for field in self.queries:
            try:
                sample = self.generate_sample_query(field, 0, max_depth)
                if sample:
                    queries[field.get('name')] = f"query {{ {sample} }}"
            except Exception as e:
                logger.warning(f"Query generation failed for {field.get('name')}: {e}")
        return queries

    def generate_all_mutations(self, max_depth: int = 2) -> Dict[str, str]:
        mutations = {}
        for field in self.mutations:
            try:
                sample = self.generate_sample_query(field, 0, max_depth)
                if sample:
                    mutations[field.get('name')] = f"mutation {{ {sample} }}"
            except Exception as e:
                logger.warning(f"Mutation generation failed for {field.get('name')}: {e}")
        return mutations

    # -----------------------------------------------------------------
    # Security-relevant field flagging
    # -----------------------------------------------------------------

    @staticmethod
    def _tokenize(name: str) -> List[str]:
        """Split a field name into lowercase word tokens (camelCase / snake / kebab)."""
        out: List[str] = []
        for part in re.split(r'[_\-]', name or ''):
            out += re.findall(r'[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+', part)
        return [t.lower() for t in out]

    def find_dangerous_fields(self) -> Dict[str, List[str]]:
        """
        Flag fields that touch sensitive PII, auth, or system config.
        Token-based: 'monkey'/'keyboard' no longer trip 'key', 'author' no longer
        trips 'auth'. 'key' flags only alongside api/secret/private/access.
        """
        dangerous = defaultdict(list)
        for type_name, type_def in self.type_map.items():
            if type_def.get('kind') != 'OBJECT' or str(type_name).startswith('__'):
                continue
            for field in type_def.get('fields', []) or []:
                fname = field.get('name', '')
                tokens = set(self._tokenize(fname))
                hit = bool(tokens & self._SENSITIVE_TOKENS) or \
                    any(pair <= tokens for pair in self._SENSITIVE_PAIRS)
                if hit:
                    dangerous[type_name].append(fname)
        return dict(dangerous)

    def find_idor_prone_fields(self) -> List[Dict]:
        """Flags queries/mutations taking ID arguments, prime targets for Insecure Direct Object References."""
        idor_fields = []
        for field in self.queries + self.mutations:
            for arg in field.get('args', []):
                arg_name = arg.get('name', '').lower()
                arg_type = self.resolve_type_ref(arg.get('type', {}))

                # If the argument is an ID type, or a string explicitly named id/uuid
                if 'ID' in arg_type or arg_name in ['id', 'uuid', 'userid', 'accountid', 'profileid']:
                    idor_fields.append({
                        'field': field.get('name'),
                        'arg': arg.get('name'),
                        'arg_type': arg_type,
                        'type': 'query' if field in self.queries else 'mutation'
                    })
        return idor_fields

    def summarize(self) -> Dict:
        return {
            'total_types': len([t for t in self.types if not t.get('name', '').startswith('__')]),
            'query_fields': len(self.queries),
            'mutation_fields': len(self.mutations),
            'subscription_fields': len(self.subscriptions),
            'dangerous_fields': self.find_dangerous_fields(),
            'idor_prone_fields': self.find_idor_prone_fields(),
            'sample_queries': self.generate_all_queries(),
            'sample_mutations': self.generate_all_mutations(),
        }