"""
Flask app for testing the SMART on FHIR OAuth stuff
Build from this tutorial: http://docs.smarthealthit.org/tutorials/authorization/
And using requests-oauthlib: http://requests-oauthlib.readthedocs.io/en/latest/index.html
"""
from flask import Flask, redirect, request, session, render_template
from requests_oauthlib import OAuth2Session
#from urllib import urlencode
import json
import logging
import http.client
import warnings
import os

#import ssl
#ssl._create_default_https_context = ssl._create_unverified_context
# Enable lots of debug logging
http.client.HTTPConnection.debuglevel = 1
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True

# Replace these with the values you get when you register you app in the SMART sandbox
client_id = "5291d554-5eff-4d25-978d-8d4a858793b0"
client_secret = "AOTZbt-JjjR8Ik4deAqK4cV07DHKRTVKe66ZpRx9U2Ksdb9oj5N-WYkaV2DRq7XKPHKxwMZtPSZaav2fWKG81eo"
#client_id = "2d3e10ec-fe61-4b2e-965d-8cafbcde0ede"
#client_secret = "APDiwOV2Lf2aa4qd5lpXhD-jTkSiHxpf5nBIxy6kwhFMK3992kGomdZai6cO5Mtvla2VF2kUEa4gUpqmgaMXn48"
redirect_uri = "https://104.40.150.115:5000/callback"

# Scopes to request from the SMART server
scope = [ \
    "openid", \
    "patient/*.*", \
    "profile", \
    "launch" \
]

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SESSION_TYPE'] = 'filesystem'
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

@app.route('/')
def index():
    return "SMART on FHIR test client - please either launch from the SMART sandbox, or <a href='/standalone'>click here to test a standalone launch</a>"

@app.route('/standalone')
def standalone():
    session['serviceUri'] = "https://sb-fhir-stu3.smarthealthit.org/smartstu3/data"
    #session['serviceUri'] = "http://52.232.115.121:9071/smartdstu2/data"
    # Go to the server and get the auth endpoint URLs from it's CapabilityStatement
    getAuthEndpointFromServerConformance(session['serviceUri'])
    # Now, start the authorization process against the auth endpoint
    return authorize_user()

"""
This is the main launch URL called by the SMART on FHIR sandbox (or any SMART on FHIR enabled EPR)
"""
@app.route('/smart-app')
def launch():

    # Get some launch parameters from the calling EHR system
    serviceUri = request.args.get('iss') #  https://sb-fhir-stu3.smarthealthit.org/smartstu3/data
    launchContextId = request.args.get('launch')
    # Store launch context in the session
    session['launchContextId'] = launchContextId
    session['serviceUri'] = serviceUri
    
    print ("App launched from SMART sandbox, with issuer URL: "+serviceUri)

    # Go to the server and get the auth endpoint URLs from it's CapabilityStatement
    getAuthEndpointFromServerConformance(serviceUri)
    
    # Now, start the authorization process against the auth endpoint
    return authorize_user()

"""
Go to the specified FHIR server and retrieve it's CapabilityStatement to obtain the OAuth details
"""
def getAuthEndpointFromServerConformance(serviceUri):
    # The issuer is the server endpoint - get it's conformance profile to find the auth URL
    conformanceResource = getRemoteResource(serviceUri)
    # Parse the oauth URLs from the profile
    conformanceJSON = json.loads(conformanceResource)
    
    authorizeUrl = ''
    tokenUrl = ''
    
    # Nasty hacky unsafe parsing - perhaps look to use either the python fhir client, or a jsonpath library?
    for entry in conformanceJSON["rest"][0]["security"]["extension"][0]["extension"]:
        if entry['url'] == 'authorize':
            authorizeUrl = entry['valueUri']
        elif entry['url'] == 'token':
            tokenUrl = entry['valueUri']

    print ("Got an authorization URL from the capabilitystatement:"+authorizeUrl)
    print ("Got a token URL from the capabilitystatement:"+tokenUrl)

    # Store the relevant parameters in the session to use for authorizing
    session['authorizeUrl'] = authorizeUrl
    session['tokenUrl'] = tokenUrl

"""
Use the python oauth2 client to call the authorization endpoint
"""
def authorize_user():
    smart_auth_session = OAuth2Session(client_id)
    
    if 'launchContextId' in session:
        authorization_url, state = smart_auth_session.authorization_url(session['authorizeUrl'], \
								    aud=session['serviceUri'], \
								    launch=session['launchContextId'])
    else:
        authorization_url, state = smart_auth_session.authorization_url(session['authorizeUrl'], \
                                    aud=session['serviceUri'])

    # State is used to prevent CSRF, keep this for later.
    session['oauth_state'] = state
    
    print ("Redirecting to authorization URL:"+authorization_url)
    return redirect(authorization_url)


"""
Callback URL called by authorization server once the user has logged in.
Takes their authorization code and calls the token endpoint to get an access token.
"""
@app.route("/callback", methods=["GET", "POST"])
def callback():
    # Retrieving an access token
    smart_auth_session = OAuth2Session(client_id, scope=scope, redirect_uri=redirect_uri, state=session['oauth_state'])
    token_url = session['tokenUrl']
    
    token_response = smart_auth_session.fetch_token(token_url, client_secret=client_secret, \
                               authorization_response=request.url)

    session['oauth_token'] = token_response
    
    if 'patient' in session['oauth_token']:
        # Get the patient ID passed in with the token
        patient_id = token_response['patient']    
        return render_template('results.html', patient = json.loads(getPatientDetails(patient_id)))
    else:
        return getPatientList()

"""
Access a protected FHIR resource from the SMART server, passing our access token in the request
"""
def getPatientDetails(patient_id):
    protected_resource_request = OAuth2Session(client_id, token=session['oauth_token'])
    fhir_root = session['serviceUri']
    patient_url = fhir_root+"/Patient/"+patient_id
    return json.dumps(protected_resource_request.get(patient_url).json())

def getPatientList():
    protected_resource_request = OAuth2Session(client_id, token=session['oauth_token'])
    fhir_root = session['serviceUri']
    patient_url = fhir_root+"/Patient/SMART-1032702"
    print('\n')
    print('\n')
    print(patient_url)
    return json.dumps(protected_resource_request.get(patient_url).json())

"""
Takes the base FHIR server URL and uses it to retrieve a conformance resource for the server
"""
def getRemoteResource(serviceUri):

    remoteEndpoint = (serviceUri + '/metadata')[8:]
    #remoteEndpoint = (serviceUri + '/metadata')[7:]
    separator = remoteEndpoint.find('/')
    host = remoteEndpoint[:separator]
    path = remoteEndpoint[separator:]
    conn = http.client.HTTPSConnection(host)
    #conn = http.client.HTTPConnection(host)
    conn.request("GET", path)
    response = conn.getresponse()
    resultResource = response.read().decode('utf-8')
    return resultResource

"""
Initialise our Flask server in debug mode
"""
if __name__ == '__main__':
    #import os
    #os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    #os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
    #app.secret_key = os.urandom(24)
    #app.config['SESSION_TYPE'] = 'filesystem'
    #app.run(host="0.0.0.0", port=5000, debug=True)
    app.run()

