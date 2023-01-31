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

        //-- CM2M ------------------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CM2M: public CApostolModule {
        private:

            CStringListPairs m_Profiles;

            CHTTPProxyManager m_ProxyManager;

            void InitMethods() override;

            static bool CheckAuthorizationData(const CHTTPRequest &Request, CAuthorization &Authorization);

            void VerifyToken(const CString &Token);

            CHTTPProxy *GetProxy(CHTTPServerConnection *AConnection);

        protected:

            void DoProxy(CHTTPServerConnection *AConnection);

            bool DoProxyExecute(CTCPConnection *AConnection);
            void DoProxyException(CTCPConnection *AConnection, const Delphi::Exception::Exception &E);
            void DoEventHandlerException(CPollEventHandler *AHandler, const Delphi::Exception::Exception &E) override;

            void DoProxyConnected(CObject *Sender);
            void DoProxyDisconnected(CObject *Sender);

        public:

            explicit CM2M(CModuleProcess *AProcess);

            ~CM2M() override = default;

            static class CM2M *CreateModule(CModuleProcess *AProcess) {
                return new CM2M(AProcess);
            }

            bool CheckAuthorization(CHTTPServerConnection *AConnection, CAuthorization &Authorization);

            static void InitConfig(const CIniFile &IniFile, const CString &Profile, CStringList &Config);

            void Initialization(CModuleProcess *AProcess) override;

            bool Enabled() override;
            bool CheckLocation(const CLocation &Location) override;

        };
    }
}

using namespace Apostol::Workers;
}
#endif //APOSTOL_M2M_HPP
