# MercadoLibre's Golang SDK

This is the official GO SDK for MercadoLibre's Platform.

## How do I install it?

You can download the latest build at:
    https://github.com/mercadolibre/go-sdk/archive/master.zip

How do I install it using go:

Just run the following command within your $GOPATH

```bash
go get github.com/mercadolibre/sdk
```

And that's it!

## How do I start using it?

To get the link to redirect the user and obtain the needed info to start using ML API,
you need first to generate the URL for user authentication and authorization.

After calling this URL, you will be able to obtain the CLIENT_CODE for later being used while client creation.
```go
url := sdk.GetAuthURL(CLIENT_ID, sdk.MLA, "https://www.example.com")
```

Now you can instantiate a ```Meli``` object. You'll need to pass a ```clientId```, ```clientCode``` and a ```clientSecret```.
You can obtain both after creating your own application. For more information on this please read: [creating an application](http://developers.mercadolibre.com/application-manager/)

```go
client, err := sdk.Meli(CLIENT_ID, CLIENT_CODE, CLIENT_SECRET, "https://www.example.com")
```
With this instance you can start interacting with MercadoLibre's APIs.

There are some design considerations worth to mention.
This SDK is just a thin layer on top of an http client to handle all the OAuth WebServer flow for you.


## Making GET calls

```go
resp, err := client.Get("/users/me")

if err != nil {
	log.Printf("Error %s\n", err.Error())
}
userInfo, _:= ioutil.ReadAll(resp.Body)
fmt.Printf("response:%s\n", userInfo)

```

## Making POST calls

```go
client, err := sdk.Meli(CLIENT_ID, CLIENT_CODE, CLIENT_SECRET, "https://www.example.com")

body :=	"{\"title\":\"Item de test - No Ofertar\",\"category_id\":\"MLA1912\",\"price\":10,\"currency_id\":\"ARS\",\"available_quantity\":1,\"buying_mode\":\"buy_it_now\",\"listing_type_id\":\"bronze\",\"condition\":\"new\",\"description\": \"Item:,  Ray-Ban WAYFARER Gloss Black RB2140 901  Model: RB2140. Size: 50mm. Name: WAYFARER. Color: Gloss Black. Includes Ray-Ban Carrying Case and Cleaning Cloth. New in Box\",\"video_id\": \"YOUTUBE_ID_HERE\",\"warranty\": \"12 months by Ray Ban\",\"pictures\":[{\"source\":\"http://upload.wikimedia.org/wikipedia/commons/f/fd/Ray_Ban_Original_Wayfarer.jpg\"},{\"source\":\"http://en.wikipedia.org/wiki/File:Teashades.gif\"}]}"

resp, err = client.Post("/items", body)

if err != nil {
    log.Printf("Error %s\n", err.Error())
}
userInfo, _= ioutil.ReadAll(resp.Body)
fmt.Printf("response:%s\n", userInfo)

```
## Making PUT calls

```go
client, err := sdk.Meli(CLIENT_ID, CLIENT_CODE, CLIENT_SECRET, "https://www.example.com")
change := "{\"available_quantity\": 6}"

resp, err = client.Put("/items/" + item.Id, &change)

if err != nil {
    log.Printf("Error %s\n", err.Error())
}
userInfo, _= ioutil.ReadAll(resp.Body)
fmt.Printf("response:%s\n", userInfo)
```
## Making DELETE calls

```go
client, err := sdk.Meli(CLIENT_ID, CLIENT_CODE, CLIENT_SECRET, "https://www.example.com")
client.Delete("/items/123")
```

## Community

You can contact us if you have questions using the standard communication channels described in the [developer's site](http://developers-forum.mercadolibre.com/)

## I want to contribute!

That is great! Just fork the project in github. Create a topic branch, write some code, and add some tests for your new code.
You can find some examples by taking a look at the main.go file.

To run the tests run ```make test```.

Thanks for helping!