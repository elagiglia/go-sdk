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
*/

package sdk

import (
    "testing"
    "log"
    "fmt"
    "net/http"
    "io/ioutil"
    "strings"
    "sync"
)

const (
    API_TEST = "http://localhost:3000"
    CLIENT_ID = 123456
    CLIENT_SECRET = "client secret"
    CLIENT_CODE = "valid code with refresh token"
)

func Test_URL_for_authentication_is_properly_return(t *testing.T) {

    expectedUrl := "https://auth.mercadolibre.com.ar/authorization?response_type=code&client_id=123456&redirect_uri=http%3A%2F%2Fsomeurl.com"

    url := GetAuthURL(CLIENT_ID, MLA, "http://someurl.com")

    if url != expectedUrl {
        log.Printf("Error: The URL is different from the one that was expected.")
        log.Printf("expected %s", expectedUrl)
        log.Printf("obtained %s", url)
        t.FailNow()
    }

}

func Test_GET_public_API_sites_works_properly ( t *testing.T){

    client, err := newTestAnonymousClient(API_TEST)

    if err != nil {
        log.Printf("Error:%s\n", err)
        t.FailNow()
    }
    //Public APIs do not need Authorization
    resp, err := client.Get("/sites")

    if err != nil {
        log.Printf("Error:%s\n", err)
        t.FailNow()
    }

    if resp.StatusCode != http.StatusOK {
        t.FailNow()
    }

    body, err := ioutil.ReadAll(resp.Body)

    if err != nil || string(body) == ""{
        t.FailNow()
    }
}

func Test_GET_private_API_users_works_properly (t *testing.T){

    client, err := newTestClient(CLIENT_ID, CLIENT_CODE, CLIENT_SECRET, "https://www.example.com", API_TEST)

    _, err = client.Get("/users/me")

    if err != nil {
        fmt.Printf("Error: %s\n", err)
        t.FailNow()
    }
}

func Test_POST_a_new_item_works_properly_when_token_IS_EXPIRED(t *testing.T){

    client, err := newTestClient(CLIENT_ID, CLIENT_CODE, CLIENT_SECRET, "https://www.example.com", API_TEST)

    body := "{\"foo\":\"bar\"}"
    resp, err := client.Post("/items", body)

    if err != nil {
        log.Printf("Error while posting a new item %s\n", err)
        t.FailNow()
    }

    if resp.StatusCode != http.StatusCreated {
        log.Printf("Error while posting a new item status code: %s\n", resp.StatusCode)
        t.FailNow()
    }
}

func Test_POST_a_new_item_works_properly_when_token_IS_NOT_EXPIRED (t *testing.T){

    client, err := newTestClient(CLIENT_ID, CLIENT_CODE, CLIENT_SECRET, "https://www.example.com", API_TEST)

    body := "{\"foo\":\"bar\"}"
    resp, err := client.Post("/items", body)

    if err != nil {
        log.Printf("Error while posting a new item %s\n", err)
        t.FailNow()
    }

    if resp.StatusCode != http.StatusCreated {
        log.Printf("Error while posting a new item status code: %s\n", resp.StatusCode)
        t.FailNow()
    }
}

func Test_PUT_a_new_item_works_properly_when_token_IS_NOT_EXPIRED (t *testing.T){

    client, err := newTestClient(CLIENT_ID, CLIENT_CODE, CLIENT_SECRET, "https://www.example.com", API_TEST)

    body := "{\"foo\":\"bar\"}"
    resp, err := client.Put("/items/123", &body)

    if err != nil {
        log.Printf("Error while posting a new item %s\n", err)
        t.FailNow()
    }

    if resp.StatusCode != http.StatusOK {
        log.Printf("Error while putting a new item. Status code: %s\n", resp.StatusCode)
        t.FailNow()
    }
}

func Test_PUT_a_new_item_works_properly_when_token_IS_EXPIRED (t *testing.T){

    client, err := newTestClient(CLIENT_ID, CLIENT_CODE, CLIENT_SECRET, "https://www.example.com", API_TEST)

    body := "{\"foo\":\"bar\"}"
    resp, err := client.Put("/items/123", &body)

    if err != nil {
        log.Printf("Error while posting a new item %s\n", err)
        t.FailNow()
    }

    if resp.StatusCode != http.StatusOK {
        log.Printf("Error while putting a new item. Status code: %s\n", resp.StatusCode)
        t.FailNow()
    }
}

func Test_DELETE_an_item_returns_200_when_token_IS_NOT_EXPIRED (t *testing.T){

    client, err := newTestClient(CLIENT_ID, CLIENT_CODE, CLIENT_SECRET, "https://www.example.com", API_TEST)

    resp, err := client.Delete("/items/123")

    if err != nil {
        log.Printf("Error while deleting an item %s\n", err)
        t.FailNow()
    }

    if resp.StatusCode != http.StatusOK {
        log.Printf("Error while putting a new item. Status code: %s\n", resp.StatusCode)
        t.FailNow()
    }
}

func Test_DELETE_an_item_returns_200_when_token_IS_EXPIRED (t *testing.T){

    client, err := newTestClient(CLIENT_ID, CLIENT_CODE, CLIENT_SECRET, "https://www.example.com", API_TEST)

    resp, err := client.Delete("/items/123")

    if err != nil {
        log.Printf("Error while deleting an item %s\n", err)
        t.FailNow()
    }
    if resp.StatusCode != http.StatusOK {
        log.Printf("Error while putting a new item. Status code: %s\n", resp.StatusCode)
        t.FailNow()
    }
}

func Test_AuthorizationURL_adds_a_params_separator_when_needed(t *testing.T)  {

    auth := newAuthorizationURL(API_URL+ "/authorizationauth")
    auth.addGrantType(AUTHORIZATION_CODE)

    url := API_URL + "/authorizationauth?" + "grant_type=" + AUTHORIZATION_CODE

    if strings.Compare(url, auth.string()) != 0 {
        log.Printf("url was different from what was expected\n expected: %s \n obtained: %s \n", url, auth.string())
        t.FailNow()
    }
}

func Test_AuthorizationURL_adds_a_query_param_separator_when_needed(t *testing.T)  {

    auth := newAuthorizationURL(API_URL + "/authorizationauth")
    auth.addGrantType(AUTHORIZATION_CODE)
    auth.addClientId(1213213)

    url := API_URL + "/authorizationauth?" + "grant_type=" + AUTHORIZATION_CODE + "&client_id=1213213"

    if strings.Compare(url, auth.string()) != 0 {
        log.Printf("url was different from what was expected\n expected: %s \n obtained: %s \n", url, auth.string())
        t.FailNow()
    }
}

func Test_only_one_token_refresh_call_is_done_when_several_threads_are_executed(t *testing.T){

    client, err := newTestClient(CLIENT_ID, CLIENT_CODE, CLIENT_SECRET, "https://www.example.com", API_TEST)

    if err != nil {
        log.Printf("Error during Client instantation %s\n", err)
        t.FailNow()
    }
    client.auth.ExpiresIn = 0
    refreshTok = hookForTesting

    wg.Add(100)
    for i := 0; i< 100 ; i++ {
       go callHttpMethod(client)
    }
    wg.Wait()

    if counter > 1 {
        t.FailNow()
    }
}

var counter = 0;
var m = sync.Mutex{}

func hookForTesting(client *Client) error {
    hookRefreshToken(client)
    m.Lock()
    counter++
    fmt.Printf("counter %d", counter)
    m.Unlock()
    return nil
}
var wg sync.WaitGroup

func callHttpMethod(client *Client){
    defer wg.Done()
    client.Get("/users/me")
}