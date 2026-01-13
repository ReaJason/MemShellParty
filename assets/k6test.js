import http from 'k6/http';
import {check, sleep} from 'k6';

export const options = {
    rps: 4500,
    vus: 10,
    duration: '5m',
};

export default function () {
    const res = http.get('http://localhost:8082/app/test');
    check(res, {
        'status is 200': (r) => r.status === 200,
    });
    sleep(1);
}
