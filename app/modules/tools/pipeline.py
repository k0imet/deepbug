# modules/tools/pipeline.py

import asyncio
import aiohttp
import aiodns
import async_timeout
from asyncio import Queue
from typing import List, Dict, Callable, Optional, Any
from app.utils.url_utils import urlparse

from app.utils.logger import get_logger
from app.utils.subprocess_runner import run_command

logger = get_logger()


class ReconPipeline:
    def __init__(self, config: Dict):
        self.config = config
        self.subdomain_scanner = SubdomainScanner(config)  # you'll need to import
        self.port_scanner = PortScanner(config)
        self.httpx_path = config['tools']['paths'].get('httpx', 'httpx')

    async def producer(self, domain: str, queue: Queue, progress_callback: Optional[Callable] = None):
        """Discover subdomains and push them to the queue."""
        logger.info(f"Producer: Discovering subdomains for {domain}")
        # Run subdomain scan (synchronous for now, but we can make it async)
        # For simplicity, we'll use the existing synchronous method in a thread
        subdomains_df = await asyncio.to_thread(
            self.subdomain_scanner.perform_subdomain_scan, domain, None
        )
        live_hosts_df = subdomains_df.get('live_hosts', pd.DataFrame())
        if not live_hosts_df.empty:
            urls = live_hosts_df['URL'].tolist()
            for url in urls:
                await queue.put(url)
                if progress_callback:
                    progress_callback(0.5, f"Discovered {len(urls)} live hosts")
        logger.info(f"Producer: Enqueued {queue.qsize()} URLs")

    async def consumer(self, queue: Queue, progress_callback: Optional[Callable] = None):
        """Process URLs: port scan, HTTP probe, GraphQL detection, etc."""
        async with aiohttp.ClientSession() as session:
            while True:
                try:
                    url = await queue.get()
                    if url is None:
                        break
                    logger.info(f"Consumer: Processing {url}")
                    # Run port scan (async)
                    ports = await self._async_port_scan(url)
                    # Run HTTP probe (httpx)
                    http_info = await self._async_http_probe(url, session)
                    # Run GraphQL detection
                    graphql_endpoints = await self._async_graphql_detect(url, session)
                    # Save results (or push to another queue)
                    # For now, just log
                    if progress_callback:
                        progress_callback(0.8, f"Processed {url}")
                    queue.task_done()
                except Exception as e:
                    logger.error(f"Consumer error: {e}")
                    queue.task_done()

    async def _async_port_scan(self, url: str) -> List:
        # For now, run nmap in a thread
        host = urlparse(url).netloc.split(':')[0]
        cmd = ['nmap', '-p', '80,443,8080,8443', '--open', '-T4', host]
        stdout, stderr, ret = await asyncio.to_thread(run_command, cmd, timeout=60)
        if ret == 0:
            return [line for line in stdout.splitlines() if 'open' in line]
        return []

    async def _async_http_probe(self, url: str, session: aiohttp.ClientSession) -> Dict:
        try:
            async with session.get(url, timeout=10) as resp:
                return {
                    'url': url,
                    'status': resp.status,
                    'headers': dict(resp.headers),
                    'length': len(await resp.text())
                }
        except:
            return {}

    async def _async_graphql_detect(self, url: str, session: aiohttp.ClientSession) -> List[str]:
        # Common GraphQL paths
        paths = ['/graphql', '/v1/graphql', '/api/graphql']
        found = []
        for path in paths:
            try:
                async with session.post(url + path, json={'query': '{ __typename }'}, timeout=5) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if 'data' in data:
                            found.append(url + path)
            except:
                pass
        return found

    async def run_pipeline(self, domain: str, progress_callback: Optional[Callable] = None):
        """Run the full pipeline."""
        queue = Queue()
        producer_task = asyncio.create_task(self.producer(domain, queue, progress_callback))
        consumer_tasks = [asyncio.create_task(self.consumer(queue, progress_callback)) for _ in range(5)]

        await producer_task
        # Wait for all items to be processed
        await queue.join()
        # Stop consumers
        for _ in consumer_tasks:
            await queue.put(None)
        await asyncio.gather(*consumer_tasks)

        if progress_callback:
            progress_callback(1.0, "Pipeline completed")