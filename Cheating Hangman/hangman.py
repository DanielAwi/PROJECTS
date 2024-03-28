#!/usr/bin/env python3

from random import choice

def read_input(guesses):
    while True:
        guess = input(f'Enter a single letter: ').lower()

        if len(guess) != 1:
            print('Enter only one letter')
        elif not guess.isalpha():
            print('''This isn't a letter, try again''')
        elif guess in guesses:
            print('You already guessed that')
        else:
            return guess


def mask_word(word, guesses):
    """Returns word with all letters not in guessed replaced with hyphens

    Args:
        word (str): the word to mask
        guessed (set): the guessed letters

    Returns:
        str: the masked word
    """
    result = ""
    for char in word:
        if char in guesses:
            result += char
        else:
            result += '-'
    return result

def game_over(guesses_remaining, hint):
    if guesses_remaining <= 0:
        return True
    if hint.count('-') == 0:
        return True
    return False

def load_words(filename, length):
    try:
        with open(filename) as f:
            words = [line.lower().strip() for line in f if len(line.strip().lower()) == length]
            return words

    except FileNotFoundError:
        print('File not found')
        return []

def read_int():
    while True:
        try:
            length = int(input('Enter a value: '))
            return length
        except:
            print('Intergers only!')

def main():
    # Game Setup
    length = read_int()
    cheat = length < 0  # cheat is boolean - True or False
    length = abs(length)
    words = load_words('words.txt', length)
    if length < 2 or len(words) == 0:  # To handle if there are no words in list or user wants to cheat
        print('No words of that size were found')
        return
    answer = choice(words)  # Randomly chooses a word from the list of words
    guesses_remaining = 5
    guesses = set()
    hint = mask_word(answer, guesses)
    if cheat:
        print(f'Potential words = {words}')

    # Game Loop
    while not game_over(guesses_remaining, hint):
        print(f'You have {guesses_remaining} guesses remaining')
        print(f'Hint: {hint}')
        print(f'Guesses Letters: {guesses}')
        # print game state

        # Get new input
        guess = read_input(guesses)

        # Update game state
        guesses.add(guess)

        # Game End Conditions
        next_hint = mask_word(answer, guesses)
        if hint != next_hint:
            # correct guess
            print(f'Correct! {guess} is in the word')
        else:
            print(f'''I'm sorry, {guess} is not in the word''')
            guesses_remaining -= 1
        hint = next_hint

    # Game end message
    if hint.count('-') == 0:
        print(f'You win!!!, the word was "{answer}"')
    else:
        print(f'You lose!, the word was "{answer}"')

def mask_test_case():
    word = 'zymurgy'
    guesses = {'y', 'm'}
    expected = '-ym---y'
    actual = mask_word(word, guesses)
    if expected != actual:
        print(f"Error mask_word({word, guessed})")
        print(f'Expected = {expected}')
        print(f'Actual = {actual}')

    word = "cheating"
    guessed = {'c', 'j', 'g', 'w'}
    expected = "c------g"
    actual = mask_word(word, guessed)

    if expected != actual:
        print(f"Error mask_word({word, guessed})")
        print(f"Expected: {expected}")
        print(f"Actual: {actual}")
    
    word = "macbook"
    guessed = {"a","o"}
    expected = "-a--oo-"
    actual = mask_word(word, guessed)

    if expected != actual:
        print(f"Error mask_word({word, guessed})")
        print(f"Expected: {expected}")
        print(f"Actual: {actual}")

    word = "hangman"
    guessed = {"m","n"}
    expected = "--n-m-n"
    actual = mask_word(word, guessed)

    if expected != actual:
        print(f"Error mask_word({word, guessed})")
        print(f"Expected: {expected}")
        print(f"Actual: {actual}")
    
if __name__ == '__main__':
    mask_test_case()
    main()