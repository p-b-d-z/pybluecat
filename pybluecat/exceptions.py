
class BluecatError(Exception):
    def __init__(self, response):
        super(BluecatError, self).__init__(response.content.decode('utf-8'))
        self.response = response
        self.status_code = response.status_code


class BluecatWebSystemError(BluecatError):
    pass

