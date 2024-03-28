
Birthday Paradox Probability Calculator

This Python program calculates the probability of shared birthdays among a group of people using the concept of the Birthday Paradox. The Birthday Paradox states that in a group of just 23 people, there is a better than even chance that two people have the same birthday.

Prerequisites
Python 3.x

Usage
Ensure you have Python installed on your system.
Download the birthday_paradox.py file.
Open a terminal or command prompt.
Navigate to the directory where birthday_paradox.py is saved.
Run the program by executing the following command:
python3 shared_birthday.py

Follow the prompts to input the desired threshold percentage.

Functionality
This program contains the following functions:

prob(people): Simulates the probability of shared birthdays among a given number of people.
test(num_trials, people): Runs multiple trials to determine the success rate of shared birthdays among a group of people.
input_int_range(low, high): Validates user input within a specified range.
main(): Orchestrates the execution of the program by setting parameters, running trials, and displaying results.
The program conducts a series of trials to determine the probability of shared birthdays among a group of people. It iterates over the number of trials specified (num_trials) and calculates the percentage of successful trials where at least two people share the same birthday. The user is prompted to input a threshold percentage, and the program calculates the number of people needed to achieve that threshold probability.

Contributors
Awi Daniel

Feel free to contribute to this project by forking it and submitting pull requests. If you encounter any issues or have suggestions for improvements, please create an issue in the repository.