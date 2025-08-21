package controllers;

import play.mvc.Controller;
import play.mvc.Http;
import play.mvc.Result;

import java.util.Arrays;

/**
 * @author ReaJason
 * @since 2025/8/21
 */
public class TestController extends Controller {
    public TestController() {
        System.out.println("init");
    }

    public Result index(Http.Request request) {
        request.queryString().forEach((k, v) -> {
            System.out.println(k + ":" + Arrays.toString(v));
        });
        return ok("hello world");
    }
}
