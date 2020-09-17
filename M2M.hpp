/*++

Program name:

  Apostol Web Service

Module Name:

  M2M.hpp

Notices:

  Module: MTS Communicator M2M XML API

Author:

  Copyright (c) Prepodobny Alen

  mailto: alienufo@inbox.ru
  mailto: ufocomp@gmail.com

--*/

#ifndef APOSTOL_M2M_HPP
#define APOSTOL_M2M_HPP
//----------------------------------------------------------------------------------------------------------------------

extern "C++" {

namespace Apostol {

    namespace Workers {

        //--------------------------------------------------------------------------------------------------------------

        //-- CSOAPProtocol ---------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CSOAPProtocol {
        public:

            static void JSONToSOAP(const CString &Action, const CJSON &Json, CString &xmlString);
            static void SOAPToJSON(const CString &Action, const CString &xmlString, CJSON &Json);

        };

        //--------------------------------------------------------------------------------------------------------------

        //-- CM2M ------------------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CM2M: public CApostolModule {
        private:

            CString m_URI;
            CString m_APIKey;
            CString m_Naming;

            CDateTime m_HeartbeatInterval;

            CHTTPProxyManager m_ProxyManager;

            CDateTime m_FixedDate;
            CDateTime m_CheckDate;

            CString m_ClientToken;

            TPairs<CStringList> m_Profile;

            void InitMethods() override;

            void SetObjectData(CHTTPServerConnection *AConnection, const CString &Token, const CJSON &Payload,
                               const CString &Agent);

            static bool CheckAuthorizationData(CRequest *ARequest, CAuthorization &Authorization);

            void VerifyToken(const CString &Token);

            CHTTPProxy *GetProxy(CHTTPServerConnection *AConnection);

        protected:

            void DoProxy(CHTTPServerConnection *AConnection);

            void DoVerbose(CSocketEvent *Sender, CTCPConnection *AConnection, LPCTSTR AFormat, va_list args);
            bool DoProxyExecute(CTCPConnection *AConnection);
            void DoProxyException(CTCPConnection *AConnection, Delphi::Exception::Exception *AException);
            void DoEventHandlerException(CPollEventHandler *AHandler, Delphi::Exception::Exception *AException);

            void DoProxyConnected(CObject *Sender);
            void DoProxyDisconnected(CObject *Sender);

        public:

            explicit CM2M(CModuleProcess *AProcess);

            ~CM2M() override = default;

            static class CM2M *CreateModule(CModuleProcess *AProcess) {
                return new CM2M(AProcess);
            }

            bool CheckAuthorization(CHTTPServerConnection *AConnection, CAuthorization &Authorization);

            void Initialization(CModuleProcess *AProcess) override;

            void Heartbeat() override;

            bool Enabled() override;
            bool CheckConnection(CHTTPServerConnection *AConnection) override;

        };
    }
}

using namespace Apostol::Workers;
}
#endif //APOSTOL_M2M_HPP
