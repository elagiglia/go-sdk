/*
Copyright [2016] [mercadolibre.com]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


**

This package allows you to interact with the Mercadolibre open platform API.
The are two main structures:
1) Client
2) Authorization

1) - This structure keeps within the secret to be used for generating the token to be sent when calling to the private APIs.
     This also provides several methods to call either public and private APIs

2) - This structure keeps the tokens and their expiration time and has to be passed by param each time a call has to be performed to any private API.
*/

package sdk

import (
    "net/url"
    "strconv"
    "bytes"
    "net/http"
    "io"
    "encoding/json"
    "io/ioutil"
    "log"
    "strings"
    "errors"
    "time"
    "sync"
    "fmt"
)

const (

    MLA = "https://auth.mercadolibre.com.ar" // Argentina
    MLB = "https://auth.mercadolivre.com.br" // Brasil
    MCO = "https://auth.mercadolibre.com.co" // Colombia
    MCR = "https://auth.mercadolibre.com.cr" // Costa Rica
    MEC = "https://auth.mercadolibre.com.ec" // Ecuador
    MLC = "https://auth.mercadolibre.cl"      // Chile
    MLM = "https://auth.mercadolibre.com.mx" // Mexico
    MLU = "https://auth.mercadolibre.com.uy" // Uruguay
    MLV = "https://auth.mercadolibre.com.ve" // Venezuela
    MPA = "https://auth.mercadolibre.com.pa" // Panama
    MPE = "https://auth.mercadolibre.com.pe" // Peru
    MPT = "https://auth.mercadolivre.pt"      // Portugal
    MRD = "https://auth.mercadolibre.com.do" // Dominicana

    AUTHORIZATION_CODE = "authorization_code"
    API_URL = "https://api.mercadolibre.com"
)

var publicClient = &Client{apiUrl:API_URL, auth:ANONYMOUS, httpClient:MeliHttpClient{}, tokenRefresher:MeliTokenRefresher{}}
var clientByUser map[string] *Client
var clientByUserMutex sync.Mutex
var ANONYMOUS = Authorization{}
var authMutex = &sync.Mutex{}

var dbg bool

func init() {
    log.SetFlags(log.LstdFlags | log.Lshortfile)
    clientByUser = make(map[string] *Client)
    dbg = true  //Set this true if you want to see debug messages
}

/*
This function returns the URL to be used for user authentication and authorization
 */
func GetAuthURL(clientId int64, base_site, callback string) string {

    authURL := newAuthorizationURL(base_site  + "/authorization")
    authURL.addResponseType("code")
    authURL.addClientId(clientId)
    authURL.addRedirectUri(callback)

    return authURL.string()
}

/*
This function returns a Client which can be used to call mercadolibre API
client id, code and secret are generated when registering your application by using Application Manager

Please, visit the following link for further information: http://developers.mercadolibre.com/application-manager/

If userCode is empty, a client will be returned, but this one is only able to query
the public mercadolibre API.

If userCode has a value, then a full authenticated client will be returned. This one is able to query either public and private
mercadolibre API.
*/
func Meli(id int64, userCode string, secret string, callBackUrl string) (*Client, error) {

    /*
    If userCode is not provided, then a generic client is returned.
    This client can be used only to access public API
     */
    if strings.Compare(userCode, "") == 0 {
        return publicClient, nil
    }

    /*
    If we are here, userCode was provided, so a full client is going to be set up, to allow full access to either private
    and public API
     */
    clientByUserMutex.Lock()
    defer clientByUserMutex.Unlock()

    //The same client is going to be returned if the same applicationId and userCode is provided.
    key := strconv.FormatInt(id, 10) + userCode

    var client *Client
    client = clientByUser[key]

    if client == nil {

        client = &Client{
            id:id,
            code:userCode,
            secret:secret,
            redirectUrl:callBackUrl,
            apiUrl:API_URL,
            httpClient:MeliHttpClient{},
            tokenRefresher:MeliTokenRefresher{},
        }

        if dbg {log.Printf("Building a client: %p for clientid:%d code:%s\n", client, id, userCode)}

        auth, err := client.authorize()

        if err != nil {
            log.Printf("error: %s", err.Error())
            return nil, err
        }

        clientByUser[key] = client
        client.auth = *auth
    }


    return client, nil
}

/**
HTTP Methods
Given that error handling for all the HTTP Methods is pretty the same, then an interface Callback is define, which is
going to be called by the handler to execute the different HTTP Methods, then check the response and handle the error
 */
type Callback interface {
    Call(apiUrl string) (*http.Response, error)
}

func httpErrorHandler(client *Client, resource string, httpMethod Callback) (*http.Response, error){

    var apiUrl *AuthorizationURL
    var err error

    if apiUrl, err = getAuthorizedURL(client, resource); err != nil {
        if dbg { log.Printf("Error %s", err) }
        return nil, err
    }

    var resp *http.Response
    if resp, err = httpMethod.Call(apiUrl.string()); err != nil {
        log.Printf("Error while calling url: %s \n Error: %s", apiUrl.string(), err)
        return nil, err
    }

    return resp, nil
}
/*
HTTP Methods to be called by httpErrorHandler
 */
type HttpGet struct{
    httpClient HttpClient
}

func (callback HttpGet) Call(url string) (*http.Response, error){
    return callback.httpClient.Get(url)
}

type HttpPost struct{
    httpClient HttpClient
    body string
}
func (callback HttpPost) Call(url string) (*http.Response, error){
    return callback.httpClient.Post(url, "application/json", bytes.NewReader([]byte(callback.body)))
}

type HttpPut struct{
    httpClient HttpClient
    body string
}
func (callback HttpPut) Call(url string) (*http.Response, error){
    return callback.httpClient.Put(url, strings.NewReader(callback.body))
}

type HttpDelete struct{
    httpClient HttpClient
}
func (callback HttpDelete) Call(url string) (*http.Response, error){
    return callback.httpClient.Delete(url, nil)
}

type Client struct {
    apiUrl      string
    id          int64
    secret      string
    code        string
    redirectUrl string
    auth        Authorization
    httpClient  HttpClient
    tokenRefresher TokenRefresher
}


/*
This method returns an Authorization object which contains the needed tokens
to interact with ML API
 */
func (client *Client) authorize() (*Authorization, error) {

    authURL := newAuthorizationURL(client.apiUrl + "/oauth/token")
    authURL.addGrantType(AUTHORIZATION_CODE)
    authURL.addClientId(client.id)
    authURL.addClientSecret(client.secret)
    authURL.addCode(client.code)
    authURL.addRedirectUri(client.redirectUrl)

    var resp *http.Response
    var err error
    if resp, err = client.httpClient.Post(authURL.string(), "application/json", *(new(io.Reader))); err != nil {
        log.Printf("Error when posting: %s", err)
        return nil, err
    }

    body, err := ioutil.ReadAll(resp.Body)
    resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, errors.New(fmt.Sprintf("Ups, there was an error: %s", body))
    }

    authorization := new(Authorization)
    if err := json.Unmarshal(body, authorization); err != nil {
        log.Printf("Error while receiving the authorization %s %s", err.Error(), body)
        return nil, err
    }

    authorization.ReceivedAt = time.Now().Unix()
    return authorization, nil
}

func (client *Client) refreshToken() error{
    return client.tokenRefresher.RefreshToken(client)
}

func (client *Client) Get(resourcePath string) (*http.Response, error) {

    return httpErrorHandler(client, resourcePath, HttpGet{httpClient:client.httpClient})
}

func (client *Client) Post(resourcePath string, body string) (*http.Response, error){

    return httpErrorHandler(client, resourcePath, HttpPost{httpClient:client.httpClient, body:body})
}

func (client *Client) Put(resourcePath string, body string) (*http.Response, error){

    return httpErrorHandler(client, resourcePath, HttpPut{httpClient:client.httpClient, body:body})
}

func (client *Client) Delete(resourcePath string ) (*http.Response, error) {

    return httpErrorHandler(client, resourcePath, HttpDelete{httpClient:client.httpClient})
}

/*
This method returns the URL + Token to be used by each HTTP request.
If Token needs to be refreshed, then this method will send a POST to ML API to refresh it.
 */
func getAuthorizedURL(client *Client, resourcePath string) (*AuthorizationURL, error){

    finalUrl := newAuthorizationURL(client.apiUrl + resourcePath)
    var err error

    if client.auth != ANONYMOUS {

        authMutex.Lock()

       if client.auth.isExpired() {

           if dbg {log.Printf("Token has expired....Refreshing it...\n")}

           err := client.refreshToken()

            if err != nil {
                if dbg {log.Printf("Error while refreshing token %s\n", err.Error())}
                return nil, err
            }
       }

        authMutex.Unlock()
        finalUrl.addAccessToken(client.auth.AccessToken)
    }

    return finalUrl, err
}


type Authorization struct {
    AccessToken  string  `json:"access_token"`
    TokenType    string  `json:"token_type"`
    ExpiresIn    int16   `json:"expires_in"`
    ReceivedAt   int64
    RefreshToken string  `json:"refresh_token"`
    Scope        string  `json:"scope"`
}

func (auth Authorization) isExpired() bool {
    if dbg {log.Printf("received at:%d expires in: %d\n", auth.ReceivedAt, auth.ExpiresIn)}
    return ((auth.ReceivedAt + int64(auth.ExpiresIn)) <= (time.Now().Unix() + 60))
}

/*
This struct allows adding all the params needed to the URL to be sent
to the ML API
*/
type AuthorizationURL struct{
    url bytes.Buffer
}

func (u *AuthorizationURL) addGrantType(value string) {
    u.add("grant_type=" + value)
}

func (u *AuthorizationURL) addClientId(value int64) {
    u.add("client_id=" + strconv.FormatInt(value, 10))
}

func (u *AuthorizationURL) addClientSecret(value string) {
    u.add("client_secret=" + url.QueryEscape(value))
}

func (u *AuthorizationURL) addCode(value string) {
    u.add("code=" + url.QueryEscape(value))
}

func (u *AuthorizationURL) addRedirectUri(uri string) {
    u.add("redirect_uri=" + url.QueryEscape(uri))
}

func (u *AuthorizationURL) addRefreshToken(t string) {
    u.add("refresh_token=" + url.QueryEscape(t))
}

func (u *AuthorizationURL) addResponseType(value string) {
    u.add("response_type=" + url.QueryEscape(value))
}

func (u *AuthorizationURL) addAccessToken(t string){
    u.add("access_token=" + url.QueryEscape(t))
}

func (u *AuthorizationURL) string() string {
    return u.url.String()
}

func (u *AuthorizationURL) add(value string) {

    if !strings.Contains(u.url.String(), "?"){
        u.url.WriteString("?" + value)
    } else if strings.LastIndex("&",u.url.String()) >= u.url.Len(){
        u.url.WriteString(value)
    } else {
        u.url.WriteString("&" + value)
    }
}

func newAuthorizationURL(baseURL string) *AuthorizationURL{
    authURL := new(AuthorizationURL)
    authURL.url.WriteString(baseURL)
    return authURL
}

type HttpClient interface {
    Get(url string) (*http.Response, error)
    Post(url string, bodyType string, body io.Reader) (*http.Response, error)
    Put(url string, body io.Reader) (*http.Response, error)
    Delete(url string, body io.Reader) (*http.Response, error)
}

type MeliHttpClient struct {

}

func (httpClient MeliHttpClient) Get(url string) (*http.Response, error){
    return http.Get(url)
}

func (httpClient MeliHttpClient) Post(url string, bodyType string, body io.Reader) (*http.Response, error) {

    return http.Post(url, bodyType, body)
}

func (httpClient MeliHttpClient) Put(url string, body io.Reader) (*http.Response, error){

    return httpClient.executeHttpRequest(http.MethodPut, url, body)
}

func (httpClient MeliHttpClient) Delete(url string, body io.Reader) (*http.Response, error){

    return httpClient.executeHttpRequest(http.MethodDelete, url, body)

}

func (httpClient MeliHttpClient) executeHttpRequest(method string, url string, body io.Reader) (*http.Response, error) {

    req, err := http.NewRequest(method, url, body)

    if err != nil {
        log.Printf("Error when creating %s request %s.", method, err.Error())
        return nil, err
    }

    resp, err := http.DefaultClient.Do(req)

    if err != nil {
        log.Printf("Error while calling url: %s\n Error: %s", url, err.Error())
        return nil, err
    }

    return resp, nil
}


type TokenRefresher interface {
     RefreshToken(*Client) error
}

type MeliTokenRefresher struct {

}

/*
This method has side effects. Alters the token that is within the client.
Every time this method is called, then locking has to be used to avoid different
methods to modify the client
 */
func (refresher MeliTokenRefresher) RefreshToken(client *Client) error {

    const REFRESH_TOKEN = "refresh_token"

    authorizationURL := newAuthorizationURL(client.apiUrl + "/oauth/token")
    authorizationURL.addGrantType(REFRESH_TOKEN)
    authorizationURL.addClientId(client.id)
    authorizationURL.addClientSecret(client.secret)
    authorizationURL.addRefreshToken(client.auth.RefreshToken)

    var resp *http.Response
    var err error

    if resp, err = client.httpClient.Post(authorizationURL.string(), "application/json", *(new(io.Reader))); err != nil {
    //if resp, err = client.Post(authorizationURL.string(), ""); err != nil {
        if dbg {log.Printf("Error: %s\n", err.Error())}
        return err
    }

    if resp.StatusCode != http.StatusOK {
        return errors.New("Refreshing token returned status code " + resp.Status)
    }

    body, err := ioutil.ReadAll(resp.Body)
    resp.Body.Close()

    if err := json.Unmarshal(body, &(client.auth)); err != nil {
        if dbg {log.Printf("Error while receiving the authorization %s %s", err.Error(), body)}
        return err
    }

    client.auth.ReceivedAt = time.Now().Unix()

    if dbg {log.Printf("auth received at: %d expires in:%d\n", client.auth.ReceivedAt, client.auth.ExpiresIn)}
    return nil
}
