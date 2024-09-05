package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	responseType = "code"
	redirectURI  = "http://localhost:8080/callback"
	grantType    = "authorization_code"
)

var secrets map[string]interface{}
var oauth struct {
	clientId            string
	clientSecret        string
	scope               string
	state               string
	codeVerifier        string
	codeChallengeMethod string
	codeChallenge       string
	authEndpoint        string
	tokenEndpoint       string
}

func readJson() {
	file, err := os.Open("client_secret.json")
	if err != nil {
		log.Fatalf("Failed to open client_secret.json: %v", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		log.Fatalf("Failed to read client_secret.json: %v", err)
	}

	if err := json.Unmarshal(data, &secrets); err != nil {
		log.Fatalf("Failed to unmarshal JSON: %v", err)
	}
}

func setUp() {
	readJson()

	oauth.clientId = secrets["web"].(map[string]interface{})["client_id"].(string)
	oauth.clientSecret = secrets["web"].(map[string]interface{})["client_secret"].(string)
	oauth.authEndpoint = "https://accounts.google.com/o/oauth2/v2/auth?"
	oauth.tokenEndpoint = "https://www.googleapis.com/oauth2/v4/token"
	oauth.state = "xyz"
	oauth.scope = "https://www.googleapis.com/auth/photoslibrary.appendonly" // スコープを設定
	oauth.codeVerifier = generateCodeVerifier()
	oauth.codeChallengeMethod = "S256"
	oauth.codeChallenge = generateCodeChallenge(oauth.codeVerifier)
}

func generateCodeVerifier() string {
	verifier := make([]byte, 32)
	if _, err := rand.Read(verifier); err != nil {
		log.Fatalf("Failed to generate code verifier: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(verifier)
}

func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func start(w http.ResponseWriter, req *http.Request) {
	authEndpoint := oauth.authEndpoint

	values := url.Values{}
	values.Add("response_type", responseType)
	values.Add("client_id", oauth.clientId)
	values.Add("state", oauth.state)
	values.Add("scope", oauth.scope)
	values.Add("redirect_uri", redirectURI)

	// PKCE用パラメータ
	values.Add("code_challenge_method", oauth.codeChallengeMethod)
	values.Add("code_challenge", oauth.codeChallenge)

	// 認可エンドポイントにリダイレクト
	http.Redirect(w, req, authEndpoint+values.Encode(), http.StatusFound)
}

func callback(w http.ResponseWriter, req *http.Request) {
	query := req.URL.Query()

	result, err := tokenRequest(query)
	if err != nil {
		log.Printf("Failed to request token: %v", err)
		http.Error(w, "Failed to request token", http.StatusInternalServerError)
		return
	}
	accessToken := result["access_token"].(string)

	uploadToken, err := uploadPhoto(accessToken, "image1.jpg")
	if err != nil {
		log.Printf("Failed to upload photo: %v", err)
		http.Error(w, "Failed to upload photo", http.StatusInternalServerError)
		return
	}

	if err := addPhotoToLibrary(accessToken, uploadToken); err != nil {
		log.Printf("Failed to add photo to library: %v", err)
		http.Error(w, "Failed to add photo to library", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Photo added to Google Photos library successfully!")
}

func tokenRequest(query url.Values) (map[string]interface{}, error) {
	values := url.Values{}
	values.Add("client_id", oauth.clientId)
	values.Add("client_secret", oauth.clientSecret)
	values.Add("grant_type", grantType)
	values.Add("code", query.Get("code"))
	values.Add("redirect_uri", redirectURI)
	values.Add("code_verifier", oauth.codeVerifier)

	req, err := http.NewRequest("POST", oauth.tokenEndpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token response: %w", err)
	}

	return data, nil
}

func uploadPhoto(accessToken, filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	uploadURL := "https://photoslibrary.googleapis.com/v1/uploads"
	client := &http.Client{}
	req, err := http.NewRequest("POST", uploadURL, file)
	if err != nil {
		return "", fmt.Errorf("failed to create upload request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Goog-Upload-File-Name", "image1.jpg")
	req.Header.Set("X-Goog-Upload-Protocol", "raw")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to upload photo: %w", err)
	}
	defer resp.Body.Close()

	uploadToken, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read upload response: %w", err)
	}

	return string(uploadToken), nil
}

func addPhotoToLibrary(accessToken, uploadToken string) error {
	batchCreateURL := "https://photoslibrary.googleapis.com/v1/mediaItems:batchCreate"

	requestBody := map[string]interface{}{
		"newMediaItems": []map[string]interface{}{
			{
				"description": "Uploaded via API",
				"simpleMediaItem": map[string]string{
					"uploadToken": uploadToken,
				},
			},
		},
	}

	jsonBody, _ := json.Marshal(requestBody)
	client := &http.Client{}
	req, err := http.NewRequest("POST", batchCreateURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create add photo request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to add photo to library: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read add photo response: %w", err)
	}

	log.Printf("Add photo response: %s", string(body))
	return nil
}

func main() {
	setUp()
	http.HandleFunc("/start", start)
	http.HandleFunc("/callback", callback)
	log.Println("start server localhost:8080...")
	if err := http.ListenAndServe("localhost:8080", nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
