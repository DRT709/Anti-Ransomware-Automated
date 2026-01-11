import os

with open("C:\\Users\\Mr.Burner\\Documents\\random.txt", 'ab') as f:  # Open in append binary mode
    f.write(os.urandom(1024 * 10))  # Append 10 KB of random bytes

print("Added random bytes to the file.")
