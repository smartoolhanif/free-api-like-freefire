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
    "https://jwt-aditya.vercel.app/token"
]

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
            batch_size = 10  # Process 10 accounts at a time
            
            # Create session with longer timeout
            self.session.timeout = 30  # 30 seconds timeout
            
            for i in range(0, len(creds), batch_size):
                batch = creds[i:i + batch_size]
                threads = []
                batch_tokens = []
                
                def fetch_token(user):
                    for auth_url in AUTH_URLS:
                        try:
                            params = {'uid': user['uid'], 'password': user['password']}
                            response = self.session.get(auth_url, params=params)
                            if response.status_code == 200:
                                data = response.json()
                                token = data.get("token")
                                if token:
                                    batch_tokens.append(token)
                                    logger.info(f"Successfully got token from {auth_url} for {user['uid']}")
                                    return  # Success, no need to try other URLs
                            else:
                                logger.warning(f"Failed to fetch token from {auth_url} for {user['uid']} (server {server_key}): Status {response.status_code}")
                        except Exception as e:
                            logger.error(f"Error fetching token from {auth_url} for {user['uid']} (server {server_key}): {str(e)}")
                            continue  # Try next URL
                    
                    logger.error(f"All authentication endpoints failed for {user['uid']} (server {server_key})")
                
                # Create and start threads for batch processing
                for user in batch:
                    thread = threading.Thread(target=fetch_token, args=(user,))
                    threads.append(thread)
                    thread.start()
                
                # Wait for all threads in this batch to complete
                for thread in threads:
                    thread.join(timeout=25)  # 25 seconds timeout per batch
                
                tokens.extend(batch_tokens)
                
                # Add a small delay between batches to prevent rate limiting
                time.sleep(1)

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
