from requests.auth import AuthBase
import requests
from time import sleep
import json
import math
import uuid
from time import sleep
import time
import hmac
import hashlib
import urllib.request
import sys
import os
import urllib.parse  as urlparse
import base64

class APIKeyAuthWithExpires(AuthBase):

    """Attaches API Key Authentication to the given Request object. This implementation uses `expires`."""

    def __init__(self, apiKey, apiSecret):
        """Init with Key & Secret."""
        self.apiKey = apiKey
        self.apiSecret = apiSecret

    def __call__(self, r):
        """
        Called when forming a request - generates api key headers. This call uses `expires` instead of nonce.
        This way it will not collide with other processes using the same API Key if requests arrive out of order.
        For more details, see https://www.bitmex.com/app/apiKeys
        """
        # modify and return the request
        expires = int(round(time.time()) + 5) # 5s grace period in case of clock skew
        r.headers['api-expires'] = str(expires)
        r.headers['api-key'] = self.apiKey
        r.headers['api-signature'] = self.generate_signature(self.apiSecret, r.method, r.url, expires, r.body or '')

        return r

    def generate_signature(self, secret, verb, url, nonce, data):
        """Generate a request signature compatible with BitMEX."""
        parsedURL = urlparse.urlparse(url)
        path = parsedURL.path
        if parsedURL.query:
            path = path + '?' + parsedURL.query

        # print "Computing HMAC: %s" % verb + path + str(nonce) + data
        message = bytes(verb + path + str(nonce) + data, "utf-8")

        signature = hmac.new(secret.encode("UTF-8"), message, digestmod=hashlib.sha256).hexdigest()
        return signature




class BitMEX(object):

    """BitMEX API Connector."""

    def __init__(self, symbol=None, apiKey=None, apiSecret=None, base_uri='https://www.bitmex.com/api/v1/' 
    , orderIDPrefix='mm_bitmex_'):
        """Init connector."""
        self.base_uri = base_uri
        self.symbol = symbol
        self.apiKey = apiKey
        self.apiSecret = apiSecret
        if len(orderIDPrefix) > 13:
            raise ValueError("settings.ORDERID_PREFIX must be at most 13 characters long!")
        self.orderIDPrefix = orderIDPrefix


        # Prepare HTTPS session
        self.session = requests.Session()

    def get_json_secret_data(self, path, postdict=None, verb=None):
        url = self.base_uri + path
        if not verb:
            verb = 'POST' if postdict else 'GET'
        nonce = int(time.time())
        data=''
        try:
            message = bytes(verb + path + str(nonce) + data, "utf-8")
            signing = hmac.new(self.apiSecret.encode("UTF-8"), message, digestmod=hashlib.sha512).hexdigest()
            headers = {'api-signature': signing, 'api-key': self.apiKey, 'api-expires': str(nonce)}
            path = self.base_uri + path
            res = urllib.request.Request(path, headers=headers)
            data = json.loads(urllib.request.urlopen(res).read())
            return data
        except urllib.error.HTTPError as e:
            print('HTTPError: ', e)
            sys.exit(1)
        except json.JSONDecodeError as e:
            print('JSONDecodeError: ', e)
            sys.exit(1)

    def _curl_bitmex(self, path, query=None, postdict=None, timeout=3, verb=None):
        """Send a request to BitMEX Servers."""
        # Handle URL
        url = self.base_uri + path

        # Default to POST if data is attached, GET otherwise
        if not verb:
            verb = 'POST' if postdict else 'GET'

        # Auth: Use Access Token by default, API Key/Secret if provided
        if self.apiKey:
            auth = APIKeyAuthWithExpires(self.apiKey, self.apiSecret)

        # Make the request
        try:
            req = requests.Request(verb, url, data=postdict, auth=auth, params=query)
            prepped = self.session.prepare_request(req)
            response = self.session.send(prepped, timeout=timeout)
            # Make non-200s throw
            response.raise_for_status()

        except requests.exceptions.HTTPError as e:
            # 401 - Auth error. Re-auth and re-run this request.
            if response.status_code == 401:
                print("Token expired, reauthenticating...")
                sleep(1)
                return self._curl_bitmex(path, query, postdict, timeout, verb)

            # 404, can be thrown if order canceled does not exist.
            elif response.status_code == 404:
                if verb == 'DELETE':
                    print("Order not found: %s" % postdict['orderID'])
                    return
                print("Unable to contact the BitMEX API (404). " + \
                    "Request: %s \n %s" % (url, json.dumps(postdict)))
                exit(1)

            # 503 - BitMEX temporary downtime, likely due to a deploy. Try again
            elif response.status_code == 503:
                print("Unable to contact the BitMEX API (503), retrying. " + \
                    "Request: %s \n %s" % (url, json.dumps(postdict)))
                sleep(1)
                return self._curl_bitmex(path, query, postdict, timeout, verb)
            # Unknown Error
            else:
                print("Unhandled Error:", e, response.text)
                print("Endpoint was: %s %s" % (verb, path))
                exit(1)

        except requests.exceptions.Timeout as e:
            # Timeout, re-run this request
            print("Timed out, retrying...")
            return self._curl_bitmex(path, query, postdict, timeout, verb)

        except requests.exceptions.ConnectionError as e:
            print("Unable to contact the BitMEX API (ConnectionError). Please check the URL. Retrying. " + \
                "Request: %s \n %s" % (url, json.dumps(postdict)))
            sleep(1)
            return self._curl_bitmex(path, query, postdict, timeout, verb)

        return response.json()

    def funds(self):
        """Get your current balance."""
        return self._curl_bitmex(path="user/margin")

    def market_depth(self,depth=10):
        """Get market depth / orderbook."""
        path = "orderBook"
        return self._curl_bitmex(path=path, query={'symbol': self.symbol, 'depth': depth})
    
    def buy(self, quantity, price=None):
        """Place a buy order.
        Returns order object. ID: orderID
        price指定なしで成り行き
        """
        return self.place_order(quantity, price=None)

    def sell(self, quantity, price):
        """Place a sell order.
        Returns order object. ID: orderID
        price指定なしで成り行き
        """
        return self.place_order(-quantity, price)


    def place_order(self, quantity, price):
        """Place an order."""
        #if price < 0:
         #   raise Exception("Price must be positive.")

        endpoint = "order"
        # Generate a unique clOrdID with our prefix so we can identify it.
        clOrdID = self.orderIDPrefix + base64.b64encode(uuid.uuid4().bytes).decode('utf8').rstrip('=\n')
        postdict = {
            'symbol': self.symbol,
            'quantity': quantity,
            'price': price,
            'clOrdID': clOrdID
        }
        return self._curl_bitmex(path=endpoint, postdict=postdict, verb="POST")

    def cancel(self, orderID):
        """Cancel an existing order."""
        path = "order"
        postdict = {
            'orderID': orderID,
        }
        return self._curl_bitmex(path=path, postdict=postdict, verb="DELETE")

    def closeAllPosition(self, price=None):
        """priceを指定しないと、成り行きで全決済"""
        path = "order/closePosition"
        postdict = {
            'symbol': self.symbol,
            'price': price,
        }
        return self._curl_bitmex(path=path, postdict=postdict, verb="POST")

    def position(self):
        """open中のposition確認,無ければ[]"""
        position_json = self._curl_bitmex(path="position")
        open_position = []
        for position in position_json:
            if position['isOpen'] == True:
                open_position.append(position)
        return open_position

    def wallet(self):
        """wallet確認なぜ割り算しなればいけないのか不明"""
        return self._curl_bitmex(path="user/walletSummary")[-1]['marginBalance']/100000000


#bit_mex = BitMEX(symbol='XBTUSD', apiKey=os.environ["API_TEST_KEY"], apiSecret=os.environ["API_TEST_SECRET"], base_uri='https://testnet.bitmex.com/api/v1/')
#print(bit_mex.wallet())

