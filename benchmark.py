import time
import socket
import start_server
import matplotlib.pyplot as plt

def query_dns_server(domain, server, port):
    # Construct DNS query message
    query = construct_dns_query(domain)

    # Start timer
    start_time = time.time()

    # Send DNS query to server
    response = send_dns_query(query, server, port)

    # End timer
    end_time = time.time()

    # Calculate duration in milliseconds
    duration_ms = (end_time - start_time) * 1000

    return duration_ms

def send_dns_query(query, server, port):
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # Send DNS query
        sock.sendto(query, (server, port))

        # Receive response
        response, _ = sock.recvfrom(512)  # Assuming max UDP response size of 512 bytes

        return response

    finally:
        sock.close()

def construct_dns_query(domain):
    # Construct DNS query message
    header = b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    domain_parts = domain.split('.')
    query_parts = []

    for part in domain_parts:
        query_parts.append(len(part).to_bytes(1, byteorder='big'))
        query_parts.append(part.encode())

    query_parts.append(b'\x00')  # End of domain
    query_parts.append(b'\x00\x01')  # Query type A
    query_parts.append(b'\x00\x01')  # Query class IN

    query = header + b''.join(query_parts)

    return query

def single_domain(domain, server, port, num_requests=10):
    print(f"\nBenchmarking domain: {domain}")
    total_duration = 0
    throughput_data = []
    durations = []
    start_time = time.time()

    for i in range(num_requests):
        duration = query_dns_server(domain, server, port)
        total_duration += duration
        throughput = (i + 1) / (time.time() - start_time)  # Requests per second
        throughput_data.append(throughput)
        durations.append(duration)
        print(f"Request {i + 1}: Time taken = {duration:.2f} ms, Throughput = {throughput:.2f} req/s")

    average_duration = total_duration / num_requests
    print(f"\nAverage time taken for {num_requests} requests: {average_duration:.2f} ms")
    
    return durations, throughput_data

def run_full_benchmark(enable_cache, domain):
    server_process = start_server.start_server(enable_cache)
    print("Server PID: ", server_process.pid)
    res = start_server.verify_server()
    if res == 0:
        print("Server is running")
    else:
        print("Server is not running")
        exit(1)

    durations, throughput_data = single_domain(domain, "127.0.0.1", 2053, 25)
    
    # Stop the DNS server
    start_server.stop_server(server_process)
    
    return durations, throughput_data

if __name__ == "__main__":
    no_cache_google_durations, no_cache_google_throughput = run_full_benchmark(False, "google.com")
    with_cache_google_durations, with_cache_google_throughput = run_full_benchmark(True, "google.com")
    no_cache_instagram_durations, no_cache_instagram_throughput = run_full_benchmark(False, "instagram.com")
    with_cache_instagram_durations, with_cache_instagram_throughput = run_full_benchmark(True, "instagram.com")

    # Plotting duration data
    plt.figure(figsize=(12, 6))

    # Plot No Cache scenario
    plt.subplot(2, 2, 1)
    plt.plot(no_cache_google_durations, label="Google.com")
    plt.plot(no_cache_instagram_durations, label="Instagram.com")
    plt.xlabel("Request Number")
    plt.ylabel("Duration (ms)")
    plt.title("DNS Server Duration Benchmark - No Cache")
    plt.legend()

    # Plot With Cache scenario
    plt.subplot(2, 2, 2)
    plt.plot(with_cache_google_durations, label="Google.com")
    plt.plot(with_cache_instagram_durations, label="Instagram.com")
    plt.xlabel("Request Number")
    plt.ylabel("Duration (ms)")
    plt.title("DNS Server Duration Benchmark - With Cache")
    plt.legend()

    # Plotting throughput data
    plt.subplot(2, 2, 3)
    plt.plot(no_cache_google_throughput, label="Google.com")
    plt.plot(no_cache_instagram_throughput, label="Instagram.com")
    plt.xlabel("Request Number")
    plt.ylabel("Throughput (req/s)")
    plt.title("DNS Server Throughput Benchmark - No Cache")
    plt.legend()

    plt.subplot(2, 2, 4)
    plt.plot(with_cache_google_throughput, label="Google.com")
    plt.plot(with_cache_instagram_throughput, label="Instagram.com")
    plt.xlabel("Request Number")
    plt.ylabel("Throughput (req/s)")
    plt.title("DNS Server Throughput Benchmark - With Cache")
    plt.legend()

    plt.tight_layout()
    plt.show()
