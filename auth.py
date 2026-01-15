import logging
import urllib.parse
import urllib.error
import http.client
import json
import time
import auth

class KeycloakAdminAPIException(Exception):
    def __init__(self, message: str, error_code: int = 0):
        super().__init__(message)
        self.error_code = error_code

#API SPEC: https://www.keycloak.org/docs-api/22.0.5/rest-api/index.html#_users

class KeycloakAdminAPIClient:
    def __init__(self, authClient: auth.AuthClient, apiURL: str):
        self.apiURL = urllib.parse.urlparse(apiURL)
        if self.apiURL.hostname is None: raise Exception('Wrong apiUrl.')
        self.authClient = authClient
        
    def _get_connection(self):
        if self.apiURL.hostname is None: raise Exception('Wrong apiUrl.')
        return http.client.HTTPSConnection(self.apiURL.hostname, self.apiURL.port)
    def _get_headers(self):
        headers = {}
        headers['Authorization'] = 'bearer ' + self.authClient.get_token()
        return headers

    def _GET_JSON(self, path):
        connection = self._get_connection()
        try:
            connection.request("GET", self.apiURL.path + path, body="", headers=self._get_headers())
            res = connection.getresponse()
            httpStatusCode = res.status
            msg = res.read()  # whole response must be readed in order to do more requests using the same connection
        finally:
            connection.close()
        if httpStatusCode != 200:
            logging.root.error('KeycloakAdminAPI error. Code: %d %s' % (httpStatusCode, res.reason))
            raise KeycloakAdminAPIException('Internal server error: KeycloakAdminAPI call failed.', httpStatusCode)
        logging.root.debug('KeycloakAdminAPI call success.')
        return json.loads(msg)

    def _PUT_JSON(self, path, content):
        connection = self._get_connection()
        headers = self._get_headers()
        headers['Content-Type'] = 'application/json'
        try:
            connection.request("PUT", self.apiURL.path + path, content, headers)
            res = connection.getresponse()
            httpStatusCode = res.status
        finally:
            connection.close()
        if httpStatusCode != 204:
            logging.root.error('KeycloakAdminAPI error. Code: %d %s' % (httpStatusCode, res.reason))
            raise KeycloakAdminAPIException('Internal server error: KeycloakAdminAPI call failed.', httpStatusCode)
        logging.root.debug('KeycloakAdminAPI call success.')

    def getUserId(self, username):
        logging.root.debug('Getting user ID from KeycloakAdminAPI...')
        response = self._GET_JSON("users?exact=true&briefRepresentation=true&username="+urllib.parse.quote_plus(username))
        try:
            if len(response) == 0: return None
            if len(response) != 1: raise Exception("Unexpected response, username not unique")
            user = response[0]
            if user["username"] != username: raise Exception("Unexpected response, username not match")
            return user["id"]
        except (Exception) as e:
            logging.root.error('KeycloakAdminAPI response unexpected: %s' % (response))
            raise KeycloakAdminAPIException('Internal server error: KeycloakAdminAPI response unexpected.')

    def getUserEmail(self, userId):
        logging.root.debug('Getting user from KeycloakAdminAPI...')
        user = self._GET_JSON("users/"+userId)
        return user["email"]

    def getUserAttribute(self, userId, attributeName):
        logging.root.debug('Getting user from KeycloakAdminAPI...')
        user = self._GET_JSON("users/"+userId)
        if "attributes" in user and attributeName in user["attributes"]:
            return user["attributes"][attributeName][0] # If the attribute is repeated there will be more than one items, 
                                                        # but let's return only the first value.
        else: return None

    def setUserAttribute(self, userId, attributeName, attributeValue):
        logging.root.debug('Getting user from KeycloakAdminAPI...')
        user = self._GET_JSON("users/"+userId)
        if not "attributes" in user: user["attributes"] = {}
        if not attributeName in user["attributes"]:
            attributeValues = [attributeValue]
        else:
            attributeValues = user["attributes"][attributeName]
            attributeValues[0] = attributeValue
        user["attributes"][attributeName] = attributeValues
        logging.root.debug('Setting user attribute with KeycloakAdminAPI...')
        self._PUT_JSON("users/"+userId, json.dumps(user))

    def _POST_JSON(self, path, content):
        connection = self._get_connection()
        headers = self._get_headers()
        headers['Content-Type'] = 'application/json'
        try:
            connection.request("POST", self.apiURL.path + path, content, headers)
            res = connection.getresponse()
            httpStatusCode = res.status
        finally:
            connection.close()
        if httpStatusCode != 201:
            logging.root.error('KeycloakAdminAPI error. Code: %d %s' % (httpStatusCode, res.reason))
            raise KeycloakAdminAPIException('Internal server error: KeycloakAdminAPI call failed.', httpStatusCode)
        logging.root.debug('KeycloakAdminAPI call success.')

    def createSpecialUser(self, username, email, firstName, lastName):

        logging.root.debug('Creatingg user attribute with KeycloakAdminAPI...')
        user = {
            "requiredActions":[],
            "emailVerified":True,
            "username":username,
            "email":email,
            "firstName":firstName,
            "lastName":lastName,
            "attributes":{"companyOrOrganization":"","projects":"","eucaimNegotiationID":"","additionalComments":"","confirmation":["no"]},
            "groups":[],
            "enabled":True}

        self._POST_JSON("users", json.dumps(user))

    