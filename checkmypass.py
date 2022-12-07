import requests
import hashlib
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fatching: {res.status_code}, check the api and try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    # convert the response from api to tupple that we can loop trough
    # contains the tail of the hash and the num of time its been hacked
    # (tail,5) , returns a generator that we can loop trough
    # data returns like whis:
    # FE78E89D007285C578A1A4155D901F006E2: 8
    # FE80BD525044312D7684C3C288CC4DFF2DD: 11
    # and we want to split all the data to show [tail,count]
    # we split each line where there is ':' , and for each line in hashes we
    # use the func splitlines() that returns a lise of the lines in a string seperated at line boundaries
    hashes = (line.split(':') for line in hashes.text.splitlines())
    # then we iterate the generator and desplay each value on its own
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    # pwnedpasswords api recived only first 5 upper chars of has1 pass
    sha1Password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1Password[:5], sha1Password[5:]
    response_from_api = request_api_data(first5_char)

    return get_password_leaks_count(response_from_api, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'!!!!! {password} has been Pwend and found {count} times!!!!')
        else:
            print(":) This a good passward and never been Pwend :)")
    return 'done!'


main(sys.argv[1:])
