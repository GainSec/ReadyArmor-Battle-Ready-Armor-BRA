"""Curated wordlist for anonymization substitutions.

All words are common English nouns: lowercase, no digits, minimum 3 characters.
Security-related terms are deliberately excluded to avoid confusion in reports.

# TODO: Extend to ~5000 words for production use. The current ~300-word list
# is sufficient for development and small engagements but will hit collisions
# on larger projects with many entities to anonymize.
"""

WORDLIST: tuple[str, ...] = (
    # Animals
    "albatross", "antelope", "badger", "beaver", "bison", "bluebird",
    "buffalo", "butterfly", "camel", "cardinal", "catfish", "cheetah",
    "chipmunk", "cobra", "condor", "cougar", "crane", "cricket",
    "crocodile", "dolphin", "donkey", "dragonfly", "eagle", "elephant",
    "falcon", "flamingo", "gazelle", "giraffe", "goldfish", "gorilla",
    "grasshopper", "grizzly", "hamster", "hawk", "hedgehog", "heron",
    "hornet", "hummingbird", "iguana", "impala", "jackal", "jaguar",
    "jellyfish", "kangaroo", "kingfisher", "koala", "ladybug", "leopard",
    "lobster", "macaw", "mammoth", "mantis", "marlin", "meerkat",
    "mockingbird", "mongoose", "moose", "narwhal", "newt", "nightingale",
    "octopus", "oriole", "osprey", "otter", "owl", "oyster",
    "panther", "parrot", "peacock", "pelican", "penguin", "pheasant",
    "pigeon", "piranha", "platypus", "porcupine", "puffin", "quail",
    "rabbit", "raccoon", "raven", "reindeer", "rhino", "robin",
    "rooster", "salamander", "salmon", "seahorse", "seagull", "sparrow",
    "squid", "stallion", "starling", "stingray", "stork", "sturgeon",
    "swallow", "swordfish", "toucan", "trout", "turtle", "viper",
    "vulture", "walrus", "weasel", "whale", "woodpecker", "wombat",
    "zebra",
    # Plants & Trees
    "acacia", "bamboo", "birch", "blossom", "cactus", "cedar",
    "cherry", "chestnut", "clover", "cypress", "dahlia", "daisy",
    "dandelion", "elm", "fern", "fig", "hazel", "heather",
    "hemlock", "hibiscus", "holly", "iris", "ivy", "jasmine",
    "juniper", "lavender", "lilac", "lily", "lotus", "magnolia",
    "maple", "marigold", "moss", "oak", "olive", "orchid",
    "palm", "peony", "pine", "poplar", "primrose", "redwood",
    "rose", "sage", "sequoia", "spruce", "sunflower", "thistle",
    "tulip", "violet", "willow", "wisteria",
    # Geography & Landscape
    "alpine", "archipelago", "basin", "canyon", "cascade", "cavern",
    "cliff", "coral", "crater", "delta", "desert", "dune",
    "estuary", "fjord", "glacier", "gorge", "harbor", "highland",
    "horizon", "island", "lagoon", "mesa", "oasis", "peninsula",
    "plateau", "prairie", "ravine", "reef", "ridge", "savanna",
    "summit", "terrace", "tundra", "valley", "volcano",
    # Weather & Sky
    "aurora", "blizzard", "breeze", "cirrus", "comet", "cumulus",
    "cyclone", "drizzle", "eclipse", "ember", "frost", "gale",
    "hailstone", "lightning", "meteor", "mist", "monsoon", "nebula",
    "nimbus", "rainbow", "sleet", "solstice", "tempest", "thunder",
    "tornado", "twilight", "typhoon", "zephyr",
    # Materials & Minerals
    "amber", "basalt", "bronze", "chalk", "cobalt", "copper",
    "crystal", "diamond", "emerald", "flint", "garnet",
    "granite", "ivory", "jade", "jasper", "marble", "obsidian",
    "onyx", "opal", "pearl", "platinum", "quartz", "ruby",
    "sapphire", "silver", "slate", "topaz", "turquoise",
    # Food & Drink
    "almond", "apricot", "avocado", "banana", "barley", "basil",
    "biscuit", "brioche", "caramel", "cardamom", "cashew", "cinnamon",
    "cocoa", "coconut", "coffee", "cranberry", "cumin", "fennel",
    "ginger", "hazelnut", "lemon", "mango", "nutmeg", "papaya",
    "parsley", "peach", "pepper", "pistachio", "plum", "pumpkin",
    "raisin", "saffron", "sesame", "thyme", "truffle", "vanilla",
    "walnut",
    # Household & Objects
    "anvil", "basket", "bell", "blanket",
    "bottle", "bucket", "candle", "carousel", "chimney", "compass",
    "cradle", "curtain", "cushion", "drum", "feather", "fiddle",
    "fountain", "furnace", "gadget", "goblet", "hammer", "lantern",
    "paddle", "pendulum", "pillar", "pinwheel",
    "planter", "puzzle", "quilt", "ribbon", "saddle", "satchel",
    "spool", "thimble", "trinket", "umbrella", "wagon",
    "whistle", "windmill",
)
