from flask import current_app
from datetime import datetime, timedelta


def test_wrong_token(client, auth):
    token = auth.login('test1', 'test1')

    response = client.get('/api/AllSites', headers={"token": "wrong_value"})

    assert response.status_code == 401
    assert b'{"response": "WRONG TOKEN"}' in response.data


def test_expired_token(client, auth, app):
    token = auth.login('test1', 'test1')

    with app.app_context():
        # set session last_used field to a time 5 hours before
        current_app.db.passwordManager.sessions.find_one_and_update(
            {
                'token': token
            },
            {
                '$set':
                    {
                        'last_used': datetime.utcnow() - timedelta(hours=5)
                    }
            }
        )

    response = client.get('/api/AllSites', headers={"token": token})
    print(response.data)
    assert response.status_code == 401
    assert b'{"response": "SESSION EXPIRED"}' in response.data
