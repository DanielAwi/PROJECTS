Hangman Game

This Python script implements a simple Hangman game where the player must guess letters in a word within a limited number of attempts.

Usage
Download the hangman.py file.
Open a terminal or command prompt.
Navigate to the directory where hangman.py is saved.

Run the program by executing the following command:
python3 hangman.py

Follow the prompts to start the game.

Functionality
The script includes the following functions:

read_input(guesses): Reads a single letter input from the user and validates it.
mask_word(word, guesses): Masks the word with hyphens, revealing guessed letters.
game_over(guesses_remaining, hint): Checks if the game is over based on the remaining guesses and revealed hint.
load_words(filename, length): Loads words from a file based on their length.
read_int(): Reads an integer input from the user.
The main() function sets up the game, loads a random word from a file, and enters the game loop. Within the loop, the player guesses letters, and the game state is updated accordingly. The game continues until the player wins by guessing all the letters or loses by running out of guesses.

Testing
The script includes a mask_test_case() function to test the mask_word() function, ensuring that it properly masks words with guessed letters.

Contributors
Awi Daniel

Feel free to contribute to this project by forking it and submitting pull requests. If you encounter any issues or have suggestions for improvements, please create an issue in the repository.