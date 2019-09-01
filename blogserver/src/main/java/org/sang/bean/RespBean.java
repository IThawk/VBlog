package org.sang.bean;

/**
 * Created by sang on 2017/12/17.
 */
public class RespBean {
    private int s;
    private String status;
    private Object msg;

    public RespBean() {
    }

    public RespBean(String status, String msg) {

        this.status = status;
        this.msg = msg;
    }

    public String getStatus() {
        return status;
    }

    @Override
    public String toString() {
        return "{" +
                "status=" + s +
                ", s='" + status + '\'' +
                ", msg=" + msg +
                '}';
    }

    public void setStatus(int status) {
        this.s = status;
    }
    public static RespBean ok(String msg, Object obj) {
        return new RespBean(200, msg, obj);
    }

    private RespBean(Integer status, String msg, Object obj) {
        this.s = status;
        this.status = msg;
        this.msg = obj;
    }
    public static RespBean ok(String msg) {
        return new RespBean(200, msg, null);
    }

    public static RespBean error(String msg, Object obj) {
        return new RespBean(500, msg, obj);
    }

    public static RespBean error(String msg) {
        return new RespBean(500, msg, null);
    }
    public String getMsg() {
        return status;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }
}
