#!/usr/bin/python3

# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
""" Harnass for fuzzing https://github.com/daviddrysdale/python-phonenumbers.git """

import sys
import struct
import atheris
import phonenumbers
from phonenumbers import Leniency, NumberParseException

def helper_parse(inp):
    """ Parsing phonenumbers """
    try:
        return phonenumbers.parse(inp, None)
    except NumberParseException:
        return None

def test_is_possible_number(inp):
    """ Testing phonenumbers is_possible_number method """
    phone_number = helper_parse(inp)
    if phone_number is not None:
        phonenumbers.is_possible_number(phone_number)

def test_is_valid_number(inp):
    """ Testing phonenumbers is_valid_number method """
    phone_number = helper_parse(inp)
    if phone_number is not None:
        phonenumbers.is_valid_number(phone_number)

def test_can_be_internationally_dialled(inp):
    """ Testing phonenumbers can_be_internationally_dialled method """
    phone_number = helper_parse(inp)
    if phone_number is not None:
        phonenumbers.can_be_internationally_dialled(phone_number)

def test_length_of_geographical_area_code(inp):
    """ Testing phonenumbers length_of_geographical_area_code method """
    phone_number = helper_parse(inp)
    if phone_number is not None:
        phonenumbers.length_of_geographical_area_code(phone_number)

def test_length_of_national_destination_code(inp):
    """ Testing phonenumbers length_of_national_destination_code method """
    phone_number = helper_parse(inp)
    if phone_number is not None:
        phonenumbers.length_of_national_destination_code(phone_number)

def test_is_number_geographical(inp):
    """ Testing phonenumbers is_number_geographical method """
    phone_number = helper_parse(inp)
    if phone_number is not None:
        phonenumbers.is_number_geographical(phone_number)

def test_national_significant_number(inp):
    """ Testing phonenumbers national_significant_number method """
    phone_number = helper_parse(inp)
    if phone_number is not None:
        phonenumbers.national_significant_number(phone_number)

def test_is_possible_short_number(inp):
    """ Testing phonenumbers is_possible_short_number method """
    phone_number = helper_parse(inp)
    if phone_number is not None:
        phonenumbers.is_possible_short_number(phone_number)

def test_is_valid_short_number(inp):
    """ Testing phonenumbers is_valid_short_number method """
    phone_number = helper_parse(inp)
    if phone_number is not None:
        phonenumbers.is_valid_short_number(phone_number)

def test_expected_cost(inp):
    """ Testing phonenumbers expected_cost method """
    phone_number = helper_parse(inp)
    if phone_number is not None:
        phonenumbers.expected_cost(phone_number)

def test_connects_to_emergency_number(inp):
    """ Testing phonenumbers connects_to_emergency_number method """
    phonenumbers.connects_to_emergency_number(inp, "MA")

def test_is_emergency_number(inp):
    """ Testing phonenumbers is_emergency_number method """
    phonenumbers.is_emergency_number(inp, "MA")

def test_is_carrier_specific(inp):
    """ Testing phonenumbers is_carrier_specific method """
    phone_number = helper_parse(inp)
    if phone_number is not None:
        phonenumbers.is_carrier_specific(phone_number)

def helper_matcher(inp, leniency):
    """ Helper for phonenumbers PhoneNumberMatcher method """
    matcher = phonenumbers.PhoneNumberMatcher(inp, "US", leniency=leniency)
    if matcher.has_next():
        matcher.next()

def test_matcher_possible(inp):
    """ Testing phonenumbers PhoneNumberMatcher method, leniency: possible """
    helper_matcher(inp, Leniency.VALID)

def test_matcher_valid(inp):
    """ Testing phonenumbers PhoneNumberMatcher method, leniency: valid """
    helper_matcher(inp, Leniency.VALID)

def test_matcher_strict_grouping(inp):
    """ Testing phonenumbers PhoneNumberMatcher method, leniency: strict grouping """
    helper_matcher(inp, Leniency.STRICT_GROUPING)

def test_matcher_exact_grouping(inp):
    """ Testing phonenumbers PhoneNumberMatcher method, leniency: exact grouping """
    helper_matcher(inp, Leniency.EXACT_GROUPING)

def test_input_digit(inp):
    """ Testing phonenumbers AsYouTypeFormatter / input_digit method """
    try:
        formatter = phonenumbers.AsYouTypeFormatter("US")
        formatter.input_digit(inp)
    except TypeError:
        return

def test_input_digit_per_digit(inp):
    """ Testing phonenumbers AsYouTypeFormatter / input_digit method, digit by digit input """
    try:
        formatter = phonenumbers.AsYouTypeFormatter("US")
        for digit in inp:
            formatter.input_digit(digit)
            formatter.get_remembered_position()
    except TypeError:
        return
    except UnicodeEncodeError:
        return

def test_is_mobile_number_portable_region(inp):
    """ Testing phonenumbers is_mobile_number_portable_region method """
    phonenumbers.is_mobile_number_portable_region(inp)

def test_convert_alpha_characters_in_number(inp):
    """ Testing phonenumbers convert_alpha_characters_in_number method """
    phonenumbers.convert_alpha_characters_in_number(inp)

def test_normalize_digits_only(inp):
    """ Testing phonenumbers normalize_digits_only method """
    phonenumbers.normalize_digits_only(inp)

def test_normalize_diallable_chars_only(inp):
    """ Testing phonenumbers normalize_diallable_chars_only method """
    phonenumbers.normalize_diallable_chars_only(inp)

def test_country_mobile_token(inp):
    """ Testing phonenumbers country_mobile_token method """
    phonenumbers.country_mobile_token(inp)

def test_supported_types_for_region(inp):
    """ Testing phonenumbers supported_types_for_region method """
    phonenumbers.supported_types_for_region(inp)

def test_supported_types_for_non_geo_entity(inp):
    """ Testing phonenumbers supported_types_for_non_geo_entity method """
    phonenumbers.supported_types_for_non_geo_entity(inp)

LONGSTR = 1
MEDIUMSTR = 2
SHORTSTR = 3
SSHORTSTR = 4

TESTS = [
    (test_is_possible_number, str),
    (test_is_valid_number, str),
    (test_can_be_internationally_dialled, str),
    (test_length_of_geographical_area_code, str),
    (test_length_of_national_destination_code, str),
    (test_is_number_geographical, str),
    (test_national_significant_number, str),
    (test_is_possible_short_number, str),
    (test_is_valid_short_number, str),
    (test_expected_cost, str),
    (test_connects_to_emergency_number, LONGSTR),
    (test_is_emergency_number, LONGSTR),
    (test_is_carrier_specific, str),
    (test_matcher_possible, SHORTSTR),
    (test_matcher_valid, SHORTSTR),
    (test_matcher_strict_grouping, SHORTSTR),
    (test_matcher_exact_grouping, SHORTSTR),
    (test_input_digit, str),
    (test_input_digit_per_digit, SSHORTSTR),
    (test_is_mobile_number_portable_region, str),
    (test_convert_alpha_characters_in_number, LONGSTR),
    (test_normalize_digits_only, LONGSTR),
    (test_normalize_diallable_chars_only, LONGSTR),
    (test_country_mobile_token, str),
    (test_supported_types_for_region, str),
    (test_supported_types_for_non_geo_entity, str),
]

def get_input(input_bytes, idx):
    """ Get input of the right type/size """
    fdp = atheris.FuzzedDataProvider(input_bytes)
    if TESTS[idx][1] == str:
        return fdp.ConsumeUnicode(sys.maxsize)
    if TESTS[idx][1] == LONGSTR:
        return fdp.ConsumeUnicode(100000)
    if TESTS[idx][1] == MEDIUMSTR:
        return fdp.ConsumeUnicode(10000)
    if TESTS[idx][1] == SHORTSTR:
        return fdp.ConsumeUnicode(1000)
    if TESTS[idx][1] == SSHORTSTR:
        return fdp.ConsumeUnicode(100)
    return None

def test_one_input(input_bytes):
    """ Fuzzer's entry point """
    if len(input_bytes) < 1:
        return
    idx = struct.unpack('>B', input_bytes[:1])[0]
    if idx >= len(TESTS):
        return
    TESTS[idx][0](get_input(input_bytes[1:], idx))

def main():
    """ main function """
    atheris.Setup(sys.argv, test_one_input, enable_python_coverage=False)
    atheris.Fuzz()


if __name__ == "__main__":
    atheris.instrument_all()
    main()
