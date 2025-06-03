# app/token_manager.py
import os
import json
import threading
import time
import logging
import requests
from cachetools import TTLCache
from datetime import timedelta
import random
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

logger = logging.getLogger(__name__)

# List of available JWT generation endpoints
AUTH_URLS = [
    "https://jwtxthug.up.railway.app/token",
    "https://jwt-aditya.vercel.app/token",
    "https://hanif-swart.vercel.app/token"
]

AUTH_URL = AUTH_URLS[0]

CACHE_DURATION = timedelta(hours=7).seconds
TOKEN_REFRESH_THRESHOLD = timedelta(hours=6).seconds

def get_random_auth_url():
    return random.choice(AUTH_URLS)

class TokenCache:
    def __init__(self, servers_config):
        self.cache = TTLCache(maxsize=100, ttl=CACHE_DURATION)
        self.last_refresh = {}
        self.lock = threading.Lock()
        self.session = self._create_session()
        self.servers_config = servers_config

    def _create_session(self):
        session = requests.Session()
        
        # Configure retry strategy with exponential backoff
        retry_strategy = Retry(
            total=3,  # total number of retries
            backoff_factor=0.5,  # wait 0.5, 1, 2 seconds between retries
            status_forcelist=[500, 502, 503, 504],  # HTTP status codes to retry on
        )
        
        # Configure the adapter with the retry strategy and pooling
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=50,  # increase connection pool size
            pool_maxsize=50,
            pool_block=False
        )
        
        # Mount the adapter for both HTTP and HTTPS
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set default timeouts and headers
        session.timeout = (3.05, 15)  # (connect timeout, read timeout)
        session.headers.update({
            'Connection': 'keep-alive',
            'Accept-Encoding': 'gzip',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)'
        })
        
        return session

    def get_tokens(self, server_key):
        with self.lock:
            now = time.time()
            refresh_needed = (
                    server_key not in self.cache or
                    server_key not in self.last_refresh or
                    (now - self.last_refresh.get(server_key, 0)) > TOKEN_REFRESH_THRESHOLD
            )

            if refresh_needed:
                self._refresh_tokens(server_key)
                self.last_refresh[server_key] = now

            return self.cache.get(server_key, [])

    def _refresh_tokens(self, server_key):
        try:
            creds = self._load_credentials(server_key)
            tokens = []
            batch_size = 30  # Slightly increased batch size
            all_threads = []
            shared_tokens = []
            token_lock = threading.Lock()
            
            def fetch_token(user):
                # Try all URLs in random order until we get a valid token
                urls = random.sample(AUTH_URLS, len(AUTH_URLS))
                for url in urls:
                    try:
                        params = {'uid': user['uid'], 'password': user['password']}
                        response = self.session.get(url, params=params)
                        if response.status_code == 200:
                            data = response.json()
                            token = data.get("token")
                            if token:
                                with token_lock:
                                    if token not in shared_tokens:
                                        shared_tokens.append(token)
                                return
                    except Exception as e:
                        logger.debug(f"Error with {url} for {user['uid']}: {str(e)}")
                        continue

            thread_pool = []
            for user in creds:
                while len(thread_pool) >= batch_size:
                    # Clean up completed threads
                    thread_pool = [t for t in thread_pool if t.is_alive()]
                    if len(thread_pool) >= batch_size:
                        time.sleep(0.1)
                
                thread = threading.Thread(target=fetch_token, args=(user,))
                thread.start()
                thread_pool.append(thread)
                all_threads.append(thread)
            
            # Wait for remaining threads
            for thread in all_threads:
                thread.join(timeout=10)
            
            tokens.extend(shared_tokens)

            if tokens:
                self.cache[server_key] = tokens
                logger.info(f"Refreshed tokens for {server_key}. Count: {len(tokens)}")
            else:
                logger.warning(f"No valid tokens retrieved for {server_key}. Clearing cache for this server.")
                self.cache[server_key] = []

        except Exception as e:
            logger.error(f"Critical error during token refresh for {server_key}: {str(e)}")
            if server_key not in self.cache:
                self.cache[server_key] = []

    def _load_credentials(self, server_key):
        try:
            config_data = os.getenv(f"{server_key}_CONFIG")
            if config_data:
                return json.loads(config_data)

          
            config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', f'{server_key.lower()}_config.json')
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"Config file not found for {server_key}: {config_path}. No credentials loaded.")
                return []
        except Exception as e:
            logger.error(f"Error loading credentials for {server_key}: {str(e)}")
            return []

def get_headers(token: str):
    return {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB49"
    }
