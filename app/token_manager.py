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
        self.session = requests.Session()
        self.servers_config = servers_config

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
            batch_size = 25  # Increased batch size for faster processing
            self.session.timeout = 15  # Reduced timeout for faster failure detection
            all_threads = []
            shared_tokens = []
            token_lock = threading.Lock()
            
            def fetch_token(user):
                # Try all URLs in random order until we get a valid token
                urls = random.sample(AUTH_URLS, len(AUTH_URLS))  # Randomize URL order
                for url in urls:
                    try:
                        params = {'uid': user['uid'], 'password': user['password']}
                        response = self.session.get(url, params=params, timeout=5)
                        if response.status_code == 200:
                            data = response.json()
                            token = data.get("token")
                            if token:
                                with token_lock:
                                    if token not in shared_tokens:
                                        shared_tokens.append(token)
                                return  # Exit after getting a valid token
                    except Exception as e:
                        logger.error(f"Error with {url} for {user['uid']}: {str(e)}")
                        continue  # Try next URL
                except Exception as e:
                    logger.error(f"Error fetching token for {user['uid']} (server {server_key}): {str(e)}")
            
            # Create all threads at once
            for user in creds:
                thread = threading.Thread(target=fetch_token, args=(user,))
                all_threads.append(thread)
                thread.start()
                
                # If we've started a batch worth of threads, wait for some to complete
                if len(all_threads) >= batch_size:
                    for t in all_threads[:batch_size//2]:  # Wait for half the batch
                        t.join(timeout=10)
                    all_threads = all_threads[batch_size//2:]  # Keep remaining threads
            
            # Wait for any remaining threads
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
