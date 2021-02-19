from datetime import datetime
from secrets import token_hex


def getToken():
    return token_hex(24)


def checkToken(token, db):
    userID = None
    outcome = 0
    session = db.passwordManager.sessions.find_one(
        {
            'token': token
        }
    )
    if session is None:
        outcome = 1
        return outcome, None, None
    time_delta = (datetime.utcnow() - session['last_used'])
    total_seconds = time_delta.total_seconds()
    if (total_seconds / 60) < 240:
        userID = session['_id']
        db.passwordManager.sessions.find_one_and_update(
            {
                'token': token
            },
            {
                '$set':
                    {
                        'last_used': datetime.utcnow()
                    }
            }
        )
        return outcome, userID, session['public_key_PEM']
    else:
        db.passwordManager.sessions.delete_one(
            {
                'token': token
            }
        )
        outcome = 2
        return outcome, None, None
