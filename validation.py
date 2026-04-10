"""
payment_validation.py

Skeleton file for input validation exercise.
You must implement each validation function according to the
specification provided in the docstrings.

All validation functions must return:

    (clean_value, error_message)

Where:
    clean_value: normalized/validated value (or empty string if invalid)
    error_message: empty string if valid, otherwise error description
"""

import re
import unicodedata
from datetime import datetime
from datetime import UTC
from typing import Tuple, Dict

from flask import blueprints


# =============================
# Regular Patterns
# =============================


CARD_DIGITS_RE = re.compile(r"")     # digits only
CVV_RE = re.compile(r"")             # 3 or 4 digits
EXP_RE = re.compile(r"")             # MM/YY format
EMAIL_BASIC_RE = re.compile(r"")     # basic email structure
NAME_ALLOWED_RE = re.compile(r"")    # allowed name characters


# =============================
# Utility Functions
# =============================

def normalize_basic(value: str) -> str:
    """
    Normalize input using NFKC and strip whitespace.
    """
    return unicodedata.normalize("NFKC", (value or "")).strip()


def luhn_is_valid(number: str) -> bool:
    """
    ****BONUS IMPLEMENTATION****

    Validate credit card number using Luhn algorithm.

    Input:
        number (str) -> digits only

    Returns:
        True if valid according to Luhn algorithm
        False otherwise
    """
    # TODO: Implement Luhn algorithm
    rev = [int(ch) for ch in str(number)][::-1]
    return (sum(rev[0::2]) + sum(sum(divmod(d * 2, 10)) for d in rev[1::2])) % 10 == 0

def remove_space_hyphens(value: str) -> str:
    value = value.replace(" ", "")
    value = value.replace("-", "")
    return value

# =============================
# Field Validations
# =============================

def validate_card_number(card_number: str) -> Tuple[str, str]:
    """
    Validate credit card number.

    Requirements:
    - Normalize input -
    - Remove spaces and hyphens before validation -
    - Must contain digits only -
    - Length between 13 and 19 digits -
    - BONUS: Must pass Luhn algorithm

    Input:
        card_number (str)

    Returns:
        (card, error_message)

    Notes:
        - If invalid → return ("", "Error message")
        - If valid → return (all credit card digits, "")
    """
    # TODO: Implement validation
    #Normalize
    card_number = normalize_basic(card_number)
    #Remove space and -
    card_number = remove_space_hyphens(card_number)
    #Only digits
    if not card_number.isdigit():
        return ("", "The credit card can only contain numbers")
    #Lenght
    if len(card_number) < 13 or len(card_number) > 19: 
        return ("", "Invalid size")
    #Luhn algorithm
    if not luhn_is_valid(card_number):
        return ("", "No valid by luhn")
    return (card_number, "")

def validate_exp_date(exp_date: str) -> Tuple[str, str]:
    """
    Validate expiration date.

    Requirements:
    - Format must be MM/YY -
    - Month must be between 01 and 12 -
    - Must not be expired compared to current UTC date -
    - Optional: limit to reasonable future (e.g., +15 years) -

    Input:
        exp_date (str)

    Returns:
        (normalized_exp_date, error_message)
    """
    # TODO: Implement validation
    exp_number = exp_date[0:2] + exp_date[3:5]
    #format MM/YY
    if not exp_number.isdigit() or exp_date[2] != "/":
        return ("", "Invalid format")
    
    #Month
    if int(exp_number[0:2]) > 12 or int(exp_number[0:2]) < 1:
        return ("", "Invalid month")
    #Not expired
    today_utc = str(datetime.now(tz=UTC))
    if int(exp_number[2:4]) + 2000 < int(str(today_utc)[0:4]):
        return ("", "Expired card")
    elif int(exp_number[2:4]) + 2000 == int(str(today_utc)[0:4]) and int(str(today_utc)[5:7]) > int(exp_number[0:2]):
        return ("", "Expired card")
    #Reasonable futue
    if int(exp_number[2:4]) + 2000 > 15 + int(str(today_utc)[0:4]):
        return ("", "Invalid card, year too away")
    
    return exp_date, ""
    print("expired")

def validate_cvv(cvv: str) -> Tuple[str, str]:
    """
    Validate CVV.

    Requirements:
    - Must contain only digits
    - Must be exactly 3 or 4 digits
    - Should NOT return the CVV value for storage

    Input:
        cvv (str)

    Returns:
        ("", error_message)
        (always return empty clean value for security reasons)
    """
    # TODO: Implement validation
    #Only digits
    if not cvv.isdigit():
        return ("", "The ccv can only contain numbers")
    #3 or 4 digits
    if not (len(cvv) == 3 or len(cvv) == 4):
        return ("", "Invalid size")
    return "", ""

def validate_billing_email(billing_email: str) -> Tuple[str, str]:
    """
    Validate billing email.

    Requirements:
    - Normalize (strip + lowercase)
    - Max length 254
    - Must match basic email pattern

    Input:
        billing_email (str)

    Returns:
        (normalized_email, error_message)
    """
    # TODO: Implement validation
    #Normalize
    billing_email = normalize_basic(billing_email)
    billing_email = billing_email.lower()
    #Max lenght
    if len(billing_email) > 254:
        return "", "Invalid size"
    #Check format
    format_check = billing_email.find("@")
    if format_check == -1:
        return "", "Must contain @"
    if billing_email.count("@") != 1:
        return "", "Must contain only one @"
    if format_check == 0 or billing_email[len(billing_email)-4:] != ".com":
        return "", "Invalid format"
    return billing_email, ""

def validate_name_on_card(name_on_card: str) -> Tuple[str, str]:
    """
    Validate name on card.

    Requirements:
    - Normalize input
    - Collapse multiple spaces
    - Length between 2 and 60 characters
    - Only letters (including accents), spaces, apostrophes, hyphens

    Input:
        name_on_card (str)

    Returns:
        (normalized_name, error_message)
    """
    # TODO: Implement validation
    #Normalize
    name_on_card = normalize_basic(name_on_card)
    #Collapse spaces
    name_on_card = re.sub(' +', ' ', name_on_card)
    #Lenght
    if len(name_on_card) < 2 or len(name_on_card) > 60:
        return "", "Invalid size"
    #Only characters
    if all(x.isalpha() or x.isspace() or x =="-" or x == "'" for x in name_on_card):
        return name_on_card, ""
    return "", "Must contain only letters, spacem apostrophes, or hyphens"

def validate_phone_number(number: str) ->Tuple[int, str]:
    """
    Validate phone number.

    Requirements:
    - Only numbers
    - Eliminate spaces
    - Length between 7 and 15 characters

    Input:
        number (str)

    Returns:
        (normalized_number, error_message)
    """
    number.replace(" ","")
    if not number.isdigit():
        return "", "Must contain only numbers"
    if len(number) < 7 or len(number) > 15:
        return "", "Invalid size"
    number = int(number)
    return number, ""

def validate_password(password: str, email: str) ->Tuple[int, str]:
    """
    Validate password.

    Requirements:
    - Length between 8 and 64 characters
    - At least one capital, lower, one number
    - At least one especial ! @ # $ % ^ & * ( ) - _ = + [ ] { } < > ?
    - No space
    - Different from email 

    Input:
        password (str), email (str)

    Returns:
        (password, error_message)
    """
    
    if len(password) < 8 or len(password) > 64:
        return "", "Invalid size"
    if not (any(c.isupper() for c in password)):
        return "", "Must contain at least one capital letter"
    if not (any(c.islower() for c in password)):
        return "", "Must contain at least one lower letter"
    if not (any(c.isnumeric() for c in password)):
        return "", "Must contain at least one number"
    special = ["!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "_", "=", "+", "[", "]", "{", "}", "<", ">", "?"]
    if not (any(c in special for c in password)):
        return "", "Must contain at least one special character. ! @ # $ % ^ & * ( ) - _ = + [ ] { } < > ?"
    if any(c.isspace() for c in password):
        return "", "Cant contain spaces"
    if password == email:
        return "", "Cant be the same as the email"
    return password, ""


# =============================
# Orchestrator Function
# =============================

def validate_payment_form(
    card_number: str,
    exp_date: str,
    cvv: str,
    name_on_card: str,
    billing_email: str
) -> Tuple[Dict, Dict]:
    """
    Orchestrates all field validations.

    Returns:
        clean (dict)  -> sanitized values safe for storage/use
        errors (dict) -> field_name -> error_message
    """

    clean = {}
    errors = {}

    card, err = validate_card_number(card_number)
    if err:
        errors["card_number"] = err
    clean["card"] = card

    exp_clean, err = validate_exp_date(exp_date)
    if err:
        errors["exp_date"] = err
    clean["exp_date"] = exp_clean

    _, err = validate_cvv(cvv)
    if err:
        errors["cvv"] = err

    name_clean, err = validate_name_on_card(name_on_card)
    if err:
        errors["name_on_card"] = err
    clean["name_on_card"] = name_clean

    email_clean, err = validate_billing_email(billing_email)
    if err:
        errors["billing_email"] = err
    clean["billing_email"] = email_clean

    return clean, errors
