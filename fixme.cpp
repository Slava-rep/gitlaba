
��
#include "../db/DbConnection.h"
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>
#include "../utils/constants/DbCnst.h"
#include "../utils/constants/FieldCnst.h"
#include "../utils/constants/CollectionCnst.h"
#include "../utils/constants/UsersSettingsCnst.h"

using bsoncxx::builder::basic::kvp;

std::map<std::string, Session> SessionAgregator::currentConnections;

bool SessionAgregator::sessionDead(std::string uuidForSession) {
    auto availableSession = currentConnections.find(uuidForSession);
    if (availableSession != currentConnections.end()) {
        auto thisSession = currentConnections[uuidForSession];
        if (diffMoreTtl(thisSession.creationTime)) {
            // если сессия протухла, выкинуть её из мапы
            currentConnections.erase(uuidForSession);
            return true;
        } else {
            updateSessionTime(uuidForSession, thisSession);
            return false;
        }
    } else {
        // если сессии совсем нет в мапе, значит она не создавалась или протухла
        return true;
    }
}

void SessionAgregator::updateSessionTime(const std::string &uuidForSession, Session &thisSession) {
    // обновляем сессию, т.к. поступил новый запрос
    thisSession.creationTime = getCurrentTime();
    // кладём обновлённое значение в мапу
    currentConnections.erase(uuidForSession);
    currentConnections[uuidForSession] = thisSession;
}

bool SessionAgregator::diffMoreTtl(tm creationTime) {
    time_t seconds = time(NULL);
    tm *now = localtime(&seconds);
    auto diff = difftime(mktime(now), mktime(&creationTime));
    return diff >= TTL;
}

Session SessionAgregator::getSessionById(std::string id) {
    return currentConnections[id];
}

std::string SessionAgregator::createSession(web::json::value value) {
    std::string authInStr;
    auto userLogin = value[FieldCnst::LOGIN].as_string();
    authInStr = returnSessionIfAlreadyExists(userLogin);
    if (!authInStr.empty()) {
        if (!sessionDead(authInStr)) {
            return authInStr;
        }
    } else {
        // генерим ююид
        authInStr = generateUuid(authInStr);
        // заполняем поля в мапе
        Session session = getFieldsFromSession(userLogin);
        fillMap(authInStr, session);
    }
    return authInStr;
}

void SessionAgregator::fillMap(const std::string &authInStr, const Session &session) {
    currentConnections[authInStr].creationTime = session.creationTime;
    currentConnections[authInStr].login = session.login;
    currentConnections[authInStr].rights = session.rights;
}

const std::string SessionAgregator::returnSessionIfAlreadyExists(utility::string_t userLogin) {
    for (auto &connection : currentConnections) {
        if (userLogin == connection.second.login) {
            return connection.first;
        }
    }
    return "";
}


std::string &SessionAgregator::generateUuid(std::string &authInStr) {
    auto uuid = boost::uuids::random_generator();
    boost::uuids::uuid uuidAuth = boost::uuids::random_generator()();
    authInStr = boost::lexical_cast<std::__cxx11::string>(uuidAuth);
    return authInStr;
}

Session SessionAgregator::getFieldsFromSession(std::string &userLogin) {
    Session session;
    session.creationTime = getCurrentTime();
    session.login = userLogin;
    session.rights = getUserRights(userLogin);
    return session;
}

tm SessionAgregator::getCurrentTime() {
    time_t seconds = time(NULL);
    tm timeinfo = *localtime(&seconds);
    return timeinfo;
}

Status SessionAgregator::getUserRights(std::string &userLogin) {
    auto userRights = getUserStatusFromCollection(userLogin);
    return UserStatus::getRightByStr(userRights);
}

std::string SessionAgregator::getUserStatusFromCollection(std::string &userLogin) {
    // Вычленяем статус из коллекции "профиль"
    mongocxx::uri uri(Settings::getConnectionAuthString(UserSettingsCnst::ADMIN_LOGIN, UserSettingsCnst::ADMIN_PASSWORD));
    auto client = mongocxx::client(uri);
    mongocxx::v_noabi::database dbasedb = client[DbCnst::NAME];
    auto collection = dbasedb.collection(CollectionCnst::PROFILE);
    auto cursor = collection.find_one({getFilter(userLogin)});
    auto userRights = cursor->view()[FieldCnst::STATUS].get_utf8().value.to_string();
    return userRights;
}

bsoncxx::builder::basic::document SessionAgregator::getFilter(std::string userLogin) {
    auto filter = bsoncxx::builder::basic::document{};
    filter.append(kvp(FieldCnst::LOGIN, userLogin.c_str()));
    return filter;
}