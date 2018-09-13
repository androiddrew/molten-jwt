import pytest
from molten_jwt.exceptions import AuthenticationError
from molten_jwt.utils import get_token_from_header


def test_missing_authorization_header_in_token_retrieval():
    with pytest.raises(AuthenticationError) as err:
        get_token_from_header(None, "bearer")
        assert "missing authorization" in err.message


def test_incorrect_authorization_string(testing_token):
    with pytest.raises(AuthenticationError) as err:
        get_token_from_header("Bearer" + testing_token, "bearer")
        assert "separate Authorization" in err.message


def test_incorrect_authorization_scheme(testing_token):
    authorization = "JWT " + testing_token
    with pytest.raises(AuthenticationError) as err:
        get_token_from_header(authorization, "bearer")
        assert "try bearer" in err.message


def test_correct_token_return(testing_token):
    authorization = "Bearer " + testing_token
    token = get_token_from_header(authorization, "bearer")
    assert token == testing_token
