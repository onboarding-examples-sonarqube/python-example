def is_not_empty(value):
    if not value:
        return False
    else:
        return True

def main():
    # Input
    name = input("Enter your name: ")

    # Check if name is empty
    if is_not_empty(name):
        print("Hello, {}!".format(name))
    else:
        print("Name is empty.")

if __name__ == "__main__":
    main()

## removed the code that was causing the issues