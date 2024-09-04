package main

import (
	"bytes"
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
	response_type = "code"
	redirect_uri  = "http://localhost:8080/callback"
	grant_type    = "authorization_code"

	verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

var secrets map[string]interface{}

var oauth struct {
	clientId              string
	clientSecret          string
	scope                 string
	state                 string
	code_challenge_method string
	code_challenge        string
	authEndpoint          string
	tokenEndpoint         string
}

func readJson() {
	file, err := os.Open("client_secret.json")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}

	json.Unmarshal(data, &secrets)
}

func setUp() {

	readJson()

	oauth.clientId = secrets["web"].(map[string]interface{})["client_id"].(string)
	oauth.clientSecret = secrets["web"].(map[string]interface{})["client_secret"].(string)
	oauth.authEndpoint = "https://accounts.google.com/o/oauth2/v2/auth?"
	oauth.tokenEndpoint = "https://www.googleapis.com/oauth2/v4/token"
	oauth.state = "xyz"
	oauth.scope = "https://www.googleapis.com/auth/photoslibrary.appendonly" // スコープを設定
	oauth.code_challenge_method = "S256"

	// PKCE用に"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"をSHA256+Base64URLエンコードしたものをセット
	oauth.code_challenge = base64URLEncode()
}

func base64URLEncode() string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func start(w http.ResponseWriter, req *http.Request) {
	authEndpoint := oauth.authEndpoint

	values := url.Values{}
	values.Add("response_type", response_type)
	values.Add("client_id", oauth.clientId)
	values.Add("state", oauth.state)
	values.Add("scope", oauth.scope)
	values.Add("redirect_uri", redirect_uri)

	// PKCE用パラメータ
	values.Add("code_challenge_method", oauth.code_challenge_method)
	values.Add("code_challenge", oauth.code_challenge)

	// 認可エンドポイントにリダイレクト
	http.Redirect(w, req, authEndpoint+values.Encode(), 302)
}

func callback(w http.ResponseWriter, req *http.Request) {
	// クエリを取得
	query := req.URL.Query()

	// トークンをリクエストする
	result, err := tokenRequest(query)
	if err != nil {
		log.Println(err)
	}
	accessToken := result["access_token"].(string)

	// 画像をアップロードしてGoogle Photosに追加する
	uploadToken, err := uploadPhoto(accessToken, "test.jpg") // "test.jpg"は追加したい画像のパス
	if err != nil {
		log.Println("Failed to upload photo:", err)
		return
	}

	err = addPhotoToLibrary(accessToken, uploadToken)
	if err != nil {
		log.Println("Failed to add photo to library:", err)
		return
	}

	fmt.Fprintf(w, "Photo added to Google Photos library successfully!")
}

func tokenRequest(query url.Values) (map[string]interface{}, error) {
	tokenEndpoint := oauth.tokenEndpoint
	values := url.Values{}
	values.Add("client_id", oauth.clientId)
	values.Add("client_secret", oauth.clientSecret)
	values.Add("grant_type", grant_type)

	// 取得した認可コードをトークンのリクエストにセット
	values.Add("code", query.Get("code"))
	values.Add("redirect_uri", redirect_uri)

	// PKCE用パラメータ
	values.Add("code_verifier", verifier)

	req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("request err: %s", err)
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	log.Printf("token response : %s", string(body))
	var data map[string]interface{}
	json.Unmarshal(body, &data)

	return data, nil
}

// 写真をGoogle Photos APIのuploadsエンドポイントにアップロードし、uploadTokenを取得する関数
func uploadPhoto(accessToken, filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	uploadURL := "https://photoslibrary.googleapis.com/v1/uploads"
	client := &http.Client{}
	req, err := http.NewRequest("POST", uploadURL, file)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Goog-Upload-File-Name", "test.jpg") // アップロードするファイル名を設定
	req.Header.Set("X-Goog-Upload-Protocol", "raw")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	uploadToken, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(uploadToken), nil
}

// uploadTokenを使って写真をGoogle Photosライブラリに追加する関数
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
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	log.Printf("Add photo response: %s", string(body))
	return nil
}

func main() {
	setUp()
	http.HandleFunc("/start", start)
	http.HandleFunc("/callback", callback)
	log.Println("start server localhost:8080...")
	err := http.ListenAndServe("localhost:8080", nil)
	if err != nil {
		log.Fatal(err)
	}
}
