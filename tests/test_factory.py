from app import create_app


def test_config():
    # test create_app with wrong config name
    assert not create_app('unspecified_config')
    assert create_app('testing')
