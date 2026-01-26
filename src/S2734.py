class MyClass(object):
    def __init__(self):
        self.message = 'Hello'
        return self  # Noncompliant: a TypeError will be raised



if not a == 2:        # Noncompliant
    b = not i < 10    # Noncompliant




from typing import List

def search_first_number_without_break(elements: List[str]):
    for elt in elements:
        if elt.isnumeric():
            return elt
    else:  # Noncompliant. This will be executed every time
        raise ValueError("List does not contain any number")


if not a == 2:        # Noncompliant
    b = not i < 10    # Noncompliant