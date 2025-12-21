import re
import hashlib
import logging

# MODULE1
# Logging & Error handeling
def login_handeling():
    try:
        logging.basicConfig(
            filename="logindata.log",
            level=logging.INFO,
            format="LOG | %(levelname)s | %(asctime)s | %(message)s"
        )
    except Exception as e:
        print("😵‍💫Error setting up logger", e)

def login_attempt(msg):
    logging.info(msg)

login_handeling()

# MODULE2
# Input Validation Module
def valid_username(username):
    return username.isalpha() and len(username) > 0

def validate_password_strength(password):
    if len(password) < 8:
        return False
    uppercase = re.search(r"[A-Z]", password)
    lowercase = re.search(r"[a-z]", password)
    num = re.search(r"[0-9]", password)
    characters = re.search(r"[!#$%&?]", password)
    return all([uppercase, lowercase, num, characters])

# MODULE3
# Secure Login System (Password hashing + lockout)
class LoginSystem:
    def __init__(login):
        login.users = {}  
        login.failed_attempts = 0
        login.LOCK_LIMIT = 5
        login.create_user()

    def hash_password(login, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def create_user(login):
        try:
            print("\033[0m🫡 enter user name:\033[0m")
            username = input("\n").strip()
            while not valid_username(username):
                print("🥹 invalid username sorry:( \nTry again:")
                username = input("\n").strip()

            print("\n🤐 enter STRONG password:")
            password = input("\n").strip()
            while not validate_password_strength(password):
                print("\n\033[91m😓 Weak password \033[91m\n👻\033[93m pls make sure: \n its 8 char long \n includs upper & lowercase\n numbers \n special characters like (!#$&%?)\033[93m\n\n\033[0m Try again:\033[0m")
                password = input("\n> ").strip()

            login.users[username] = login.hash_password(password)
            print(f"\033[92m🥳user '{username}' created successfully🥳\033[92m")
            login_attempt(f"new user created: {username}")

        except Exception as e:
            print("c🥲ould not create user", e)

    def is_locked(login):
        return login.failed_attempts >= login.LOCK_LIMIT

    def login(login, username, password):
        try:
            password_hash = login.hash_password(password)

            if username not in login.users:
                login.failed_attempts += 1
                attempts_left = login.LOCK_LIMIT - login.failed_attempts
                login_attempt(f"FAILED login (unknown user): {username}")

                if login.is_locked():
                    print("\n\033[91m🤬system locked due to too many failed attempts🤬\033[91m")
                    return False

                print(f"\n\033[91m🥸 user does not exist😰\033[91m\n\033[94mAttempts left: {attempts_left}\033[94m")
                return False

            if login.users[username] != password_hash:
                login.failed_attempts += 1
                attempts_left = login.LOCK_LIMIT - login.failed_attempts
                login_attempt(f"FAILED login (wrong password): {username}")

                if login.is_locked():
                    print("\n\033[91m🤬System locked due to too many failed attempts🤬\033[91m")
                    return False

                print(f"\n\033[91m😲Incorrect password😰\033[91m\n\033[94mAttempts left: {attempts_left}\033[94m")
                return False

            login_attempt(f"SUCCESSFUL login: {username}")
            print("\n\033[92m🎊🎉🪅🪄Login successful!🪄🪅🎉🎊\033[92m")
            return True

        except Exception as e:
            print("😵‍💫Error during login", e)
            return False

# main
if __name__ == "__main__":
    system = LoginSystem()
    while not system.is_locked():
        print("\033[0m-----------------------------------------------------------------------------------------------\033[0m")
        print("\n\033[0m🙂Login to your account:\033[0m")
        user = input("😎Username:\n").strip()
        pwd = input("🤫Password:\n").strip()
        if system.login(user, pwd):
            break  

