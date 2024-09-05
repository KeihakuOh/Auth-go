# Overview
I have developed an interest in authentication systems and the Go programming language, and I want to implement OAuth 2.0 and OpenID Connect using Go.

## OAuth2.0
Flow of an Application that Uploads Photos Using OAuth 2.0 and Google Photos API
The purpose of this program is to allow a user to authenticate with Google and then use that authentication information to upload photos to Google Photos. Below is a simplified flow of the process.

### 1. Server Setup
When the program starts, the main function is called. The server is initialized and sets up two URL endpoints (/start and /callback).

/start endpoint: This endpoint initiates the authentication process.
/callback endpoint: This endpoint is used to receive information from Google after authentication. The server listens for requests on port 8080.

### 2. Google Authentication Setup (OAuth 2.0)
The setUp function is called to load the necessary information for authentication. Client ID, client secret, and other settings required for authentication are read from the client_secret.json file. The authentication endpoint (Google login page URL) and the token endpoint (to obtain access tokens) are also set up. The PKCE (Proof Key for Code Exchange) security feature is used to securely exchange tokens.

### 3. Start of Authentication
When the user accesses http://localhost:8080/start in a browser, the start endpoint is called. This endpoint redirects the user to Google's authentication page (login screen). The redirect URL includes authentication information (client ID, redirect URI, etc.). The user is then prompted to log in with Google and grant access to the app.

### 4. User Authentication and Obtaining Authorization Code
After the user authenticates with Google and grants permission to the app, Google generates an authorization code. This authorization code is sent to a predefined redirect destination (http://localhost:8080/callback).

### 5. Obtaining the Access Token
The callback endpoint is called, and the authorization code is obtained from the URL query parameters. The program uses this authorization code to send a request to Google's token endpoint to obtain an access token. An access token is a short-lived key that provides authorization to perform specific actions (in this case, uploading photos to Google Photos).

### 6. Uploading Photos to Google Photos
The access token is used to upload the specified photo file (test.jpg) to Google Photos. An upload request is sent to the uploads endpoint of the Google Photos API. If the upload is successful, an uploadToken (upload token) is returned.

### 7. Adding the Photo to the Google Photos Library
Next, the obtained uploadToken is used to add the photo to the Google Photos library. An API request is sent to register the photo in the library.

### 8. Displaying the Result
If the photo is successfully added, the callback handler displays the message "Photo added to Google Photos library successfully!" to the user.

## Prerequisites for the Program to Succeed
### Preparation:
Obtain an OAuth 2.0 client ID and client secret from the Google Cloud Console and save them in client_secret.json. Enable the Google Photos API.

### Starting the Server:
Run the code to start the server (e.g., using the go run command).

### Browser Interaction:
Access http://localhost:8080/start in a browser to begin the authentication process.

### Summary
The main purpose of this program is to allow a user to authenticate with Google and then upload photos to Google Photos. The token (access token) serves as a temporary "key" that allows the app to access Google resources (such as Photos) on behalf of the user. The authentication flow is implemented to securely obtain and use this token.




