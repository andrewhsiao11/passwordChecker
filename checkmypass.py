import requests
import hashlib
import sys

# accessing the pwnedpasswords api
# uses K-anonymity - api only gets 5 characters of SHA1 hashed password
# response returns the hashed tail of all passwords that are hashed with those 5 characters
# now can check on my side and confirm rest of hash (my password's hashed tail) -- Remain anonymous
# request data from api and return response
def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f"Error fetching: {res.status_code}, check the api and try again")
    return res


def get_password_leaks_count(hashes, hash_to_check):
    # convert list of hashes to tuple of (hash, num_times_leaked)
    hashes = (line.split(":") for line in hashes.text.splitlines())
    # check if tail matches res tail and return count of times password has been leaked
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


# check password if it exists in API response
def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


# will receive args in terminal to run all this...
def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(
                f"{password} was found {count} times... you should probably change your password...")
        else:
            print(f"{password} was NOT found in any leaks, it is safe to use.")
    return "Search completed!"

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))


# # if reading passowrds from text file
# def main():
#     with open('passkeeper.txt', 'r') as f:
#         passwordlist = []
#         for line in f:
#             content = line.strip()
#             passwordlist.append(content)

#         for password in passwordlist:
#             count = pwned_api_check(password)
#             if count:
#                 print(
#                     f"{password} was found {count} times... you should probably change your password...")
#             else:
#                 print(f"{password} was NOT found in any leaks, it is safe to use.")
#         print('Search completed!')


# if __name__ == '__main__':
#     main()
