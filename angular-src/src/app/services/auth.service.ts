import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Login, User, UserNoPW, CertReq } from '../models/User';
import { LoginComponent } from '../components/login/login.component';
import { JwtHelperService } from '@auth0/angular-jwt';

import * as forge from 'node-forge';
const pki = forge.pki;



const httpOptions = {
  headers: new HttpHeaders({
  ContentType : 'application/json',
}),
};

@Injectable({
providedIn: 'root',
})
export class AuthService {
  authToken: any;
  user: User;
  constructor(private http: HttpClient,
    public jwtHelper: JwtHelperService) {}

    prepEndpoint(ep) {
      // 1. 로컬 서버에서 개발시
      // return 'http://localhost:3000/' + ep;
      // 2. 클라우드 서버에서 운영시
         return ep;
    // }
    }

  
//서버에 사용자정보 등록을 요청하고 실패/성공의 결과를 받아서 리턴해주는 함수
registerUser(user: User): Observable<any> {
  //const registerUrl = 'http://localhost:3000/users/register';
  const registerUrl = this.prepEndpoint('users/register');
  return this.http.post<any>(registerUrl, user, httpOptions);
}

authenticateUser(login: Login): Observable<any> {
  //const loginUrl = 'http://localhost:3000/users/authenticate';
  const loginUrl = this.prepEndpoint('users/authenticate');
  return this.http.post<any>(loginUrl, login, httpOptions);
  }


storeUserData(token: any, userNoPW: UserNoPW) {
  localStorage.setItem('authToken', token);
  localStorage.setItem('userNoPW', JSON.stringify(userNoPW));
  }

  logout() {
    // localStorage.clear();
    localStorage.removeItem('authToken');
    localStorage.removeItem('userNoPW');
    }
    getProfile(): Observable<any> {
      let authToken: any = localStorage.getItem('authToken');
      // 토큰을 포함한 헤더 옵션 생성
      const httpOptions1 = {
      headers: new HttpHeaders({
      'Content-Type': 'application/json',
      Authorization: 'Bearer ' + authToken,
      }),
      };
      //const profileUrl = 'http://localhost:3000/users/profile';
      const profileUrl = this.prepEndpoint('users/profile');
      return this.http.get<any>(profileUrl, httpOptions1);
    }

    loggedIn(): boolean {
      let authToken: any = localStorage.getItem('authToken');
      return !this.jwtHelper.isTokenExpired(authToken);
      }

      getList(): Observable<any> {
        let authToken: any = localStorage.getItem('authToken');
        const httpOptions1 = {
        headers: new HttpHeaders({
        contentType: 'application/json',
        authorization: 'Bearer ' + authToken,
        }),
        };
        const listUrl = this.prepEndpoint('users/list');
        return this.http.get(listUrl, httpOptions1);
        }

        // Issuing certificate
certRequest(request, keySize): Observable<any> {
  // Key generation
  let keyPair = pki.rsa.generateKeyPair(keySize);
  let publicKey = keyPair.publicKey;
  let privateKey = keyPair.privateKey;
  let publicKeyPem = pki.publicKeyToPem(publicKey);
  let privateKeyPem = pki.privateKeyToPem(privateKey);
  // Storing private key
  localStorage.setItem('privateKey', privateKeyPem);
  // Certificate request. UTF-8 encoding.
  const req: CertReq = {
  country: forge.util.encodeUtf8(request.country),
  state: forge.util.encodeUtf8(request.state),
  locality: forge.util.encodeUtf8(request.locality),
  organization: forge.util.encodeUtf8(request.organization),
  orgUnit: forge.util.encodeUtf8(request.orgUnit),
  common: request.common, // common = username should be English
  publicKey: publicKeyPem,
  };
  const certUrl = this.prepEndpoint('users/cert');
  return this.http.post(certUrl, req, httpOptions);
  }
  // Store certificate
storeCert(cert, caCert) {
  localStorage.setItem('cert', cert);
  localStorage.setItem('caCert', caCert);
  }

  authenticateSigUser(request): Observable<any> {
    const loginUrl = this.prepEndpoint('users/authenticateSig');
    return this.http.post(loginUrl, request, httpOptions);
    }
  
}

