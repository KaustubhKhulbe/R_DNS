# R_DNS
A thread safe DNS server written in Rust. The goal was to better understand how DNS servers work and how to write concurrent and memory safe Rust code, so using several online guides and reading about the Dns Protocol, the initial version was made. I then expanded upon it by including an LRU cache.

## Features
1. Can resolve and return DNS queries via cli such as `dig`
2. Uses a LRU (Least Recently Used) caching protocol
3. Keeps an array of Cache Entries, and constantly updates the entries that have expired
4. Stores and loads the cache via `toml` files
5. Thread safe, with a thread that constantly updates the cache entries to ensure none are expried, and a thread that periodically stores the cache
6. Includes full unit tests for all modules such as the `ByteBuffer`, `DnsCache`, and `DnsRecord` (and more ...)

## Example

##### Client View
```
➜  ~ dig @127.0.0.1 -p 2053 google.com

; <<>> DiG 9.10.6 <<>> @127.0.0.1 -p 2053 google.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 3968
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;google.com.			IN	A

;; ANSWER SECTION:
google.com.		300	IN	A	142.250.72.206

;; Query time: 0 msec
;; SERVER: 127.0.0.1#2053(127.0.0.1)
;; WHEN: Tue Jun 18 22:33:38 PDT 2024
;; MSG SIZE  rcvd: 54
```
##### Server Output
```
INFO [r_dns] Server started on port 2053
INFO [r_dns::cache::cache] Saving cache to file
INFO [r_dns] Query 3968 handled successfully
INFO [r_dns] A { domain: "google.com", addr: 142.250.72.206, ttl: 300 }
```

##### Starting the Server
To start the server, simple run `cargo run <max_size> <update_interval_ms> <cache_store_interval>` and to unit test run `cargo test`

## Statistics
The project includes a full benchmarking to test the performance of the DNS server, by measuring the average query response time and the throughput. The tests have been conducted for both the server with the cache enabled and dissabled. The entire test bench can be run with `python3 benchmark.py`, which starts the server, measures the statistics, then closes it.

##### Results

![MoreData](https://github.com/KaustubhKhulbe/R_DNS/assets/66220294/34b76be2-eb1a-4423-9d5c-e75a8e7c4f4e)

We see that the cache performance far exceeds the performance without the cache. The average query time for google.com without the cache was `81.99ms`, but with the cache was `0.24ms`. Additionally, the cache allows us to get a much higher throughput. 

