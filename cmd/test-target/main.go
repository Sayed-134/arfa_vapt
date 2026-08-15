package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/clean", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "clean") })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><a href="/xss?q=test">xss</a> <a href="/sqli?id=1">sqli</a> <a href="/lfi?file=test">lfi</a><form action="/xss" method="get"><input name="q"></form></html>`)
	})
	mux.HandleFunc("/xss", func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("q")
		fmt.Fprintf(w, "reflected=%s", v)
	})
	mux.HandleFunc("/sqli", func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		if strings.ContainsAny(v, "'\"") {
			fmt.Fprint(w, "You have an error in your SQL syntax")
			return
		}
		fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("/lfi", func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("file")
		if strings.Contains(v, "passwd") {
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash")
			return
		}
		fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("url")
		if v != "" {
			w.Header().Set("Location", v)
			w.WriteHeader(http.StatusFound)
			return
		}
		fmt.Fprint(w, "ok")
	})
	log.Println("test target: http://127.0.0.1:18080")
	log.Fatal(http.ListenAndServe("127.0.0.1:18080", mux))
}
