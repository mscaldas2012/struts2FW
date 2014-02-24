package com.msc.struts2.interceptors;

import com.msc.utils.StringUtils;
import com.opensymphony.xwork2.ActionInvocation;
import com.opensymphony.xwork2.interceptor.Interceptor;
import org.apache.commons.net.util.SubnetUtils;
import org.apache.log4j.Logger;
import org.apache.struts2.ServletActionContext;

import javax.servlet.http.HttpServletRequest;

/**
 * This Interceptor allows for calls only within a given intranet, even if a given action or application is
 * exposed outside.
 *
 * The CIDR rules that can call this action can be passed as a comma delimited parameter when setting up on struts.xml
 * Ex.:
 *      <interceptor name="cdcIntranetOnly" class="gov.cdc.presentation.interceptors.IntranetSecurity">
 *          <param name="allowedCIDRs">10.0.0.0/8, 123.456.0.0/16</param>
 *      </interceptor>
 *
 * This class requires the commons project because of StringUtils dependency.
 * 
 * 
 * Created by Marcelo Caldas on 2/21/14.
 * mscaldas@gmail.com
 */
public class IntranetSecurity implements Interceptor {
    private static final Logger logger = Logger.getLogger(IntranetSecurity.class);

    private String allowedCIDRs;
    private SubnetUtils[] allowedCIDRList;

    @Override
    public void destroy() {

    }

    @Override
    public void init() {
        String[] cidrlist =  StringUtils.toArrayWithDelimiters(getAllowedCIDRs(), ",");
        this.allowedCIDRList = new SubnetUtils[cidrlist.length];
        for (int i = 0; i < allowedCIDRList.length; i++) {
            allowedCIDRList[i] = new SubnetUtils(cidrlist[i]);
        }
    }

    @Override
    public String intercept(ActionInvocation actionInvocation) throws Exception {
        HttpServletRequest request = ServletActionContext.getRequest();
        String ipAddress = request.getHeader("X-FORWARDED-FOR");
        if (ipAddress == null) {
            ipAddress = request.getRemoteAddr();
        }

        boolean found = ipNotLocalHost(ipAddress);
        for(int i = 0; i < allowedCIDRList.length && !found; i++) {
            found = allowedCIDRList[i].getInfo().isInRange(ipAddress);
        }
        if (!found) {
            throw new Exception("You can call this action only within a Intranet!");
        }
        logger.info("Caller is inside your intranet! all is good! Caller IP is " + ipAddress);
        return actionInvocation.invoke();
    }

    private boolean ipNotLocalHost(String ipAddress) {
        boolean isLocal = ipAddress.equals("127.0.0.1");

        return isLocal;
    }

    public String getAllowedCIDRs() {
        return allowedCIDRs;
    }

    public void setAllowedCIDRs(String allowedCIDRs) {
        this.allowedCIDRs = allowedCIDRs;
    }
}
