import smtplib
from random import randint

APP_PASSWORD = "qmzj thox jgrb cypa"
MY_EMAIL = "perlecatt@gmail.com"


class Verifier:

    @staticmethod
    def send_code(email):
        numbers = [str(randint(0, 10)) for x in range(4)]
        code = ''.join(numbers)
        print(3)
        with smtplib.SMTP_SSL("smtp.gmail.com", port=465) as connection:
            connection.ehlo()
            connection.login(user=MY_EMAIL, password=APP_PASSWORD)
            connection.sendmail(from_addr=MY_EMAIL,
                                to_addrs=email,
                                msg=f"Subject:Password Manager Verification Code\n\n"
                                    f"Password Manager Verification"
                                    f" code\n{code}"
                                )

        return code
