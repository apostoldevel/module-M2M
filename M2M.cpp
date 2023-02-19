/*++

Program name:

  Apostol Web Service

Module Name:

  M2M.cpp

Notices:

  Module: MTS Communicator M2M XML API

Author:

  Copyright (c) Prepodobny Alen

  mailto: alienufo@inbox.ru
  mailto: ufocomp@gmail.com

--*/

//----------------------------------------------------------------------------------------------------------------------

#include "Core.hpp"
#include "M2M.hpp"
//----------------------------------------------------------------------------------------------------------------------

#include "jwt.h"
//----------------------------------------------------------------------------------------------------------------------

#include "rapidxml.hpp"

using namespace rapidxml;
//----------------------------------------------------------------------------------------------------------------------

extern "C++" {

namespace Apostol {

    namespace Workers {

        //--------------------------------------------------------------------------------------------------------------

        //-- CM2M ------------------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        CM2M::CM2M(CModuleProcess *AProcess) : CApostolModule(AProcess, "m2m", "worker/m2m") {
            m_Headers.Add("Authorization");
            CM2M::InitMethods();
        }
        //--------------------------------------------------------------------------------------------------------------

        void CM2M::InitMethods() {
#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            m_Methods.AddObject(_T("POST")   , (CObject *) new CMethodHandler(true , [this](auto && Connection) { DoProxy(Connection); }));
            m_Methods.AddObject(_T("OPTIONS"), (CObject *) new CMethodHandler(true , [this](auto && Connection) { DoOptions(Connection); }));
            m_Methods.AddObject(_T("GET")    , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_Methods.AddObject(_T("HEAD")   , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_Methods.AddObject(_T("PUT")    , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_Methods.AddObject(_T("DELETE") , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_Methods.AddObject(_T("TRACE")  , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_Methods.AddObject(_T("PATCH")  , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_Methods.AddObject(_T("CONNECT"), (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
#else
            m_Methods.AddObject(_T("POST")   , (CObject *) new CMethodHandler(true , std::bind(&CM2M::DoProxy, this, _1)));
            m_Methods.AddObject(_T("OPTIONS"), (CObject *) new CMethodHandler(true , std::bind(&CM2M::DoOptions, this, _1)));
            m_Methods.AddObject(_T("GET")    , (CObject *) new CMethodHandler(false, std::bind(&CM2M::MethodNotAllowed, this, _1)));
            m_Methods.AddObject(_T("HEAD")   , (CObject *) new CMethodHandler(false, std::bind(&CM2M::MethodNotAllowed, this, _1)));
            m_Methods.AddObject(_T("PUT")    , (CObject *) new CMethodHandler(false, std::bind(&CM2M::MethodNotAllowed, this, _1)));
            m_Methods.AddObject(_T("DELETE") , (CObject *) new CMethodHandler(false, std::bind(&CM2M::MethodNotAllowed, this, _1)));
            m_Methods.AddObject(_T("TRACE")  , (CObject *) new CMethodHandler(false, std::bind(&CM2M::MethodNotAllowed, this, _1)));
            m_Methods.AddObject(_T("PATCH")  , (CObject *) new CMethodHandler(false, std::bind(&CM2M::MethodNotAllowed, this, _1)));
            m_Methods.AddObject(_T("CONNECT"), (CObject *) new CMethodHandler(false, std::bind(&CM2M::MethodNotAllowed, this, _1)));
#endif
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CM2M::DoProxyExecute(CTCPConnection *AConnection) {

            auto pProxyConnection = dynamic_cast<CHTTPClientConnection*> (AConnection);
            auto pProxy = dynamic_cast<CHTTPProxy*> (pProxyConnection->Client());
            auto &Reply = pProxyConnection->Reply();

            DebugReply(Reply);

            auto pConnection = pProxy->Connection();

            if (pConnection->Connected()) {
                pConnection->CloseConnection(true);

                pConnection->Reply().ContentType = CHTTPReply::json;
                pConnection->Reply().Content = CJSON(Reply.Content).ToString();

                pConnection->SendReply(Reply.Status, nullptr, true);
            }

            return true;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CM2M::DoProxyException(CTCPConnection *AConnection, const Delphi::Exception::Exception &E) {
            auto pProxyConnection = dynamic_cast<CHTTPClientConnection *> (AConnection);
            auto pProxy = dynamic_cast<CHTTPProxy *> (pProxyConnection->Client());

            Log()->Error(APP_LOG_EMERG, 0, "[%s:%d] %s", pProxy->Host().c_str(), pProxy->Port(), E.what());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CM2M::DoEventHandlerException(CPollEventHandler *AHandler, const Delphi::Exception::Exception &E) {
            auto pProxyConnection = dynamic_cast<CHTTPClientConnection *> (AHandler->Binding());
            DoProxyException(pProxyConnection, E);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CM2M::DoProxyConnected(CObject *Sender) {
            auto pConnection = dynamic_cast<CHTTPClientConnection*> (Sender);
            if (pConnection != nullptr) {
                Log()->Message(_T("[%s:%d] M2M Proxy connected."), pConnection->Socket()->Binding()->PeerIP(),
                               pConnection->Socket()->Binding()->PeerPort());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CM2M::DoProxyDisconnected(CObject *Sender) {
            auto pConnection = dynamic_cast<CHTTPClientConnection*> (Sender);
            if (pConnection != nullptr) {
                Log()->Message(_T("[%s:%d] M2M Proxy disconnected."), pConnection->Socket()->Binding()->PeerIP(),
                               pConnection->Socket()->Binding()->PeerPort());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        CHTTPProxy *CM2M::GetProxy(CHTTPServerConnection *AConnection) {
            auto pProxy = m_ProxyManager.Add(AConnection);
#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            pProxy->OnVerbose([this](auto && Sender, auto && AConnection, auto && AFormat, auto && args) { DoVerbose(Sender, AConnection, AFormat, args); });

            pProxy->OnExecute([this](auto && AConnection) { return DoProxyExecute(AConnection); });

            pProxy->OnException([this](auto && AConnection, auto && AException) { DoProxyException(AConnection, AException); });
            pProxy->OnEventHandlerException([this](auto && AHandler, auto && AException) { DoEventHandlerException(AHandler, AException); });

            pProxy->OnConnected([this](auto && Sender) { DoProxyConnected(Sender); });
            pProxy->OnDisconnected([this](auto && Sender) { DoProxyDisconnected(Sender); });
#else
            pProxy->OnVerbose(std::bind(&CM2M::DoVerbose, this, _1, _2, _3, _4));

            pProxy->OnExecute(std::bind(&CM2M::DoProxyExecute, this, _1));

            pProxy->OnException(std::bind(&CM2M::DoProxyException, this, _1, _2));
            pProxy->OnEventHandlerException(std::bind(&CM2M::DoEventHandlerException, this, _1, _2));

            pProxy->OnConnected(std::bind(&CM2M::DoProxyConnected, this, _1));
            pProxy->OnDisconnected(std::bind(&CM2M::DoProxyDisconnected, this, _1));
#endif
            return pProxy;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CM2M::VerifyToken(const CString &Token) {

            auto decoded = jwt::decode(Token);

            const auto& aud = CString(decoded.get_audience());
            const auto& alg = CString(decoded.get_algorithm());
            const auto& iss = CString(decoded.get_issuer());

            const auto& Providers = Server().Providers();

            CString Application;
            const auto Index = OAuth2::Helper::ProviderByClientId(Providers, aud, Application);
            if (Index == -1)
                throw COAuth2Error(_T("Not found provider by Client ID."));

            const auto& Provider = Providers[Index].Value();
            const auto& Secret = OAuth2::Helper::GetSecret(Provider, Application);

            CStringList Issuers;
            Provider.GetIssuers(Application, Issuers);
            if (Issuers[iss].IsEmpty())
                throw jwt::error::token_verification_exception(jwt::error::token_verification_error::issuer_missmatch);

            if (alg == "HS256") {
                auto verifier = jwt::verify()
                        .allow_algorithm(jwt::algorithm::hs256{Secret});
                verifier.verify(decoded);
            } else if (alg == "HS384") {
                auto verifier = jwt::verify()
                        .allow_algorithm(jwt::algorithm::hs384{Secret});
                verifier.verify(decoded);
            } else if (alg == "HS512") {
                auto verifier = jwt::verify()
                        .allow_algorithm(jwt::algorithm::hs512{Secret});
                verifier.verify(decoded);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CM2M::CheckAuthorizationData(const CHTTPRequest &Request, CAuthorization &Authorization) {

            const auto &caHeaders = Request.Headers;
            const auto &caCookies = Request.Cookies;

            const auto &caAuthorization = caHeaders.Values(_T("Authorization"));

            if (caAuthorization.IsEmpty()) {

                Authorization.Username = caHeaders.Values(_T("Session"));
                Authorization.Password = caHeaders.Values(_T("Secret"));

                if (Authorization.Username.IsEmpty() || Authorization.Password.IsEmpty())
                    return false;

                Authorization.Schema = CAuthorization::asBasic;
                Authorization.Type = CAuthorization::atSession;

            } else {
                Authorization << caAuthorization;
            }

            return true;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CM2M::CheckAuthorization(CHTTPServerConnection *AConnection, CAuthorization &Authorization) {

            const auto &Request = AConnection->Request();

            try {
                if (CheckAuthorizationData(Request, Authorization)) {
                    if (Authorization.Schema == CAuthorization::asBearer) {
                        VerifyToken(Authorization.Token);
                        return true;
                    }
                }

                if (Authorization.Schema == CAuthorization::asBasic)
                    AConnection->Data().Values("Authorization", "Basic");

                ReplyError(AConnection, CHTTPReply::unauthorized, "Unauthorized.");
            } catch (jwt::error::token_expired_exception &e) {
                ReplyError(AConnection, CHTTPReply::forbidden, e.what());
            } catch (jwt::error::token_verification_exception &e) {
                ReplyError(AConnection, CHTTPReply::bad_request, e.what());
            } catch (CAuthorizationError &e) {
                ReplyError(AConnection, CHTTPReply::bad_request, e.what());
            } catch (std::exception &e) {
                ReplyError(AConnection, CHTTPReply::bad_request, e.what());
            }

            return false;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CM2M::DoProxy(CHTTPServerConnection *AConnection) {

            const auto &caRequest = AConnection->Request();
            auto &Reply = AConnection->Reply();

            Reply.ContentType = CHTTPReply::json;

            auto pProxy = GetProxy(AConnection);
            auto &ProxyRequest = pProxy->Request();

            CStringList Routs;
            SplitColumns(caRequest.Location.pathname, Routs, '/');

            if (Routs.Count() < 2) {
                AConnection->SendStockReply(CHTTPReply::not_found);
                return;
            }

            CAuthorization caAuthorization;
            if (!CheckAuthorization(AConnection, caAuthorization))
                return;

            const auto& profile = caRequest.Params["profile"];
            const auto& caProfile = profile.empty() ? "main" : profile;

            const auto& uri = m_Profiles[caProfile]["uri"];
            const auto& auth = m_Profiles[caProfile]["auth"];
            const auto& token = m_Profiles[caProfile]["token"];
            const auto& naming = m_Profiles[caProfile]["naming"];

            const auto& caAction = Routs[1];

            AConnection->Data().Values("Token", caAuthorization.Token);
            AConnection->Data().Values("Action", caAction);

            AConnection->CloseConnection(false);

            CJSON Json;
            ContentToJson(caRequest, Json);

            CLocation Location(uri + "/" + (caAction == "SendMessage" ? "messages" : caAction));

            pProxy->Host() = Location.hostname;
            pProxy->Port(Location.port);
            pProxy->UsedSSL(Location.port == 443);

            const auto& caContentType = caRequest.Headers.Values("Content-Type");
            const auto& caUserAgent = caRequest.Headers.Values("User-Agent");

            ProxyRequest.Clear();

            ProxyRequest.ContentType = CHTTPRequest::json;

            ProxyRequest.Location = Location;
            ProxyRequest.UserAgent = caUserAgent;

            ProxyRequest.Content = CString().Format(R"({"options": {"from": {"sms_address": "%s"}}, "messages": [{"to": [{"msisdn": "%s"}], "content": {"short_text": "%s"}}]})",
                                                      naming.c_str(),
                                                      Json["msid"].AsString().c_str(),
                                                      Json["message"].AsString().c_str());
            ProxyRequest.CloseConnection = true;

            CHTTPRequest::Prepare(ProxyRequest, "POST", Location.pathname.c_str());
            if (!token.IsEmpty()) {
                ProxyRequest.AddHeader(_T("Authorization"), (auth.empty() ? _T("Bearer") : auth) + " " + token);
            }

            DebugRequest(ProxyRequest);

            pProxy->Active(true);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CM2M::InitConfig(const CIniFile &IniFile, const CString &Profile, CStringList &Config) {
            Config.AddPair("uri", IniFile.ReadString(Profile, "uri", "https://omnichannel.mts.ru/http-api/v1"));
            Config.AddPair("auth", IniFile.ReadString(Profile, "auth", "Basic"));
            Config.AddPair("token", IniFile.ReadString(Profile, "token", ""));
            Config.AddPair("naming", IniFile.ReadString(Profile, "naming", ""));
        }
        //--------------------------------------------------------------------------------------------------------------

        void CM2M::Initialization(CModuleProcess *AProcess) {
            CApostolModule::Initialization(AProcess);
            LoadConfig(Config()->IniFile().ReadString(SectionName().c_str(), "config", "conf/m2m.conf"), m_Profiles, InitConfig);
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CM2M::Enabled() {
            if (m_ModuleStatus == msUnknown)
                m_ModuleStatus = Config()->IniFile().ReadBool(SectionName().c_str(), "enable", false) ? msEnabled : msDisabled;
            return m_ModuleStatus == msEnabled;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CM2M::CheckLocation(const CLocation &Location) {
            return Location.pathname.SubString(0, 5) == _T("/m2m/");
        }
    }
}
}