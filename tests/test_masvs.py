from scopeward import masvs


def test_category_of():
    assert masvs.category_of("MASVS-NETWORK-1") == "MASVS-NETWORK"
    assert masvs.category_of("MASVS-STORAGE-2") == "MASVS-STORAGE"


def test_category_of_invalid():
    assert masvs.category_of("") is None
    assert masvs.category_of("NOT-A-CONTROL") is None
    assert masvs.category_of("MASVS-BOGUS-1") is None


def test_category_name():
    assert masvs.category_name("MASVS-NETWORK-1") == "Network Communication"
    assert masvs.category_name("MASVS-CRYPTO-3") == "Cryptography"
    assert masvs.category_name("bad") is None


def test_is_valid_control():
    assert masvs.is_valid_control("MASVS-AUTH-1")
    assert not masvs.is_valid_control("MASVS-AUTH")  # missing number
    assert not masvs.is_valid_control("")


def test_mastg_help_uri():
    assert masvs.mastg_help_uri("MASTG-TEST-0019").endswith("MASTG-TEST-0019")
    assert masvs.mastg_help_uri("") is None


def test_masvs_help_uri_stable():
    assert masvs.masvs_help_uri("MASVS-NETWORK-1").startswith("https://")


def test_all_categories_have_names():
    for prefix, name in masvs.MASVS_CATEGORIES.items():
        assert prefix.startswith("MASVS-")
        assert name
