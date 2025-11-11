from mysql.connector import connection
connection.MySQLConnection(host='localhost', user='sonarsource', password='')  # Noncompliant


class MyClass(object):
    def __init__(self):
        self.message = 'Hello'
        return self  # Noncompliant



def myfunc(param):
    if param is None:
        print(param.test())  

    if param == None:
        print(param.test())  

    if param is not None:
        pass
    else:
        print(param.test())  

    if param != None:
        pass
    else:
        print(param.test())  


#adding something for commit


#adding something for commit
#adding something for commit
#adding something for commit
