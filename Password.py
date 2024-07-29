from random import shuffle, randint
from zxcvbn import zxcvbn

symbols = ["%", "?", "!", ".", "-", "_", "+"]
lowercase_letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                     'u', 'v', 'w', 'x', 'y', 'z']
uppercase_letters = [letter.upper() for letter in lowercase_letters]
numbers = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0"]


def get_percentage_int(n, percent):
    return int(n * percent / 100)


class Password:

    @staticmethod
    def generate(lower, upper, number, symbol, length=10):
        characters = []

        if symbol:
            characters += symbols
        if lower:
            characters += lowercase_letters
        if upper:
            characters += uppercase_letters
        if number:
            characters += numbers

        shuffle(characters)
        characters = ''.join(characters)

        return characters[0:length]

    @staticmethod
    def strength_score_color_description_feedback(password, very_weak="dark red", weak="orange", neutral="yellow",
                                                  strong="sky blue", very_strong="light green"):
        data = []

        if len(password) > 1:
            results = zxcvbn(password)
            score = results["score"]
            description = ""
            color = ""
            if score == 0:
                color = very_weak
                description = "very weak"
            elif score == 1:
                color = weak
                description = "weak"
            elif score == 2:
                color = neutral
                description = "neutral"
            elif score == 3:
                color = strong
                description = "strong"
            elif score == 4:
                color = very_strong
                description = "very strong"
            data = [score, color, description, results["feedback"]["warning"]]

        return data
