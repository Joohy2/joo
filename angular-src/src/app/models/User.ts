export interface User {
    name: string;
    email: string;
    username: string;
    password: string;
}

export interface Login {
    username: string;
    password: string;
    } 

    // 로그인된 사용자정보의 데이터 모델.
// 보안을 위해 서버가 패스워드 정보는 제외하고 보내주었음.
export interface UserNoPW {
    _id: string;
    name: string;
    email: string;
    username: string;
}

// 인증서 발급 요청
export interface CertReq {
    country: string;
    state: string;
    locality: string;
    organization: string;
    orgUnit: string;
    common: string;
    publicKey: string;
    }
    