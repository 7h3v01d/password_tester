# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Built-in word and password lists (small; drop bigger lists into data/ to extend them)."""

COMMON_PASSWORDS = frozenset({
    "password", "123456", "123456789", "12345678", "12345", "1234567", "qwerty",
    "abc123", "password1", "111111", "123123", "admin", "letmein", "welcome",
    "monkey", "dragon", "iloveyou", "login", "master", "sunshine", "princess",
    "football", "baseball", "shadow", "superman", "trustno1", "passw0rd",
    "p@ssw0rd", "qwerty123", "1q2w3e4r", "zaq12wsx", "000000", "654321",
    "michael", "jordan", "hello", "freedom", "whatever", "qazwsx", "starwars",
    "batman", "access", "flower", "hottie", "loveme", "ashley", "bailey",
    "secret", "changeme", "default", "guest", "root", "test", "singapore",
})

COMMON_WORDS = [
    "password", "passw0rd", "qwerty", "admin", "welcome", "login", "letmein",
    "iloveyou", "monkey", "dragon", "master", "sunshine", "princess",
    "football", "baseball", "shadow", "secret", "hello", "love", "user",
    "abc", "test", "guest", "summer", "winter", "spring", "autumn", "january",
    "february", "march", "april", "june", "july", "august", "september",
    "october", "november", "december", "football", "soccer", "google",
]

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"

WORDS = tuple(sorted(set("""
acorn actor agent alarm album alpine amber anchor angle apple april arrow aspen atlas attic autumn bacon badge
baker bamboo banjo barn basil beach beacon berry bicycle birch biscuit blanket blossom bonus boxer branch breeze
bridge bronze bucket butter cabin cactus camel candle canyon carbon cargo carpet castle cedar cellar cheese cherry
chess circus citrus clover cobalt coffee comet compass copper coral cotton cougar crater crayon crimson crystal
curtain cypress daisy dancer delta desert diamond dinner dolphin donkey dragon drift eagle earth echo ember engine
falcon fabric feather fennel ferry fiddle field flame flint forest fossil fountain galaxy garden garlic ginger
glacier goblet granite grape gravel guitar hammer harbor harvest hazel helmet heron hickory honey horizon hunter
igloo island ivory jacket jaguar jasmine jelly jewel jigsaw jungle kettle kitten ladder lagoon lantern laurel
lemon lizard lobster magnet mango maple marble meadow melon meteor mirror monkey mosaic mountain muffin nebula
nectar needle nickel noodle nutmeg oasis ocean olive onion orange orchid otter oyster paddle panda parrot pebble
pepper piano pillow pioneer planet plum pocket pollen puzzle quartz rabbit radish rainbow raven reef ribbon river
rocket saddle saffron salmon sandal sapphire scarlet shadow silver sketch spiral spruce squirrel summit sunset
tablet tangerine thistle thunder tiger timber toast tomato tower trumpet tulip tundra turtle umbrella valley
velvet violet voyage walnut waffle whale willow window winter wizard yogurt zephyr zigzag
""".split())))

NAMES = frozenset("""john mary michael jessica david sarah james emma daniel olivia chris amanda matthew ashley andrew
jennifer joshua lisa robert kevin ryan nicole brian laura jason anna thomas jack lucy ben sam alex max charlie
sophie jacob lily ethan chloe liam noah mia adam zoe nathan henry oliver grace isabel hannah rachel peter""".split())
